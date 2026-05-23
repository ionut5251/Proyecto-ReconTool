from copy import deepcopy
from typing import Any, Optional

from app.services.ai_advisor import suggest_attack_vectors
from app.services.cve_lookup import build_search_keyword, lookup_cves
from app.services.ftp_probe import run_exploitation_checks
from app.services.nmap_scanner import scan_target
from app.services.playbook_advisor import build_playbook_analysis, merge_ai_with_playbook
from app.services.vuln_db import load_vulnerabilities_db


def _merge_cve_findings(local: Optional[dict], nvd_items: list[dict]) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()

    if local:
        entry = {
            "cve": local.get("cve"),
            "cvss": local.get("cvss"),
            "severity": local.get("severity"),
            "description": local.get("description"),
            "source": "local",
        }
        if entry["cve"]:
            seen.add(entry["cve"])
            findings.append(entry)

    for item in nvd_items:
        if "error" in item:
            findings.append(item)
            continue
        cve_id = item.get("cve")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        findings.append(item)

    return findings


def enrich_scan_with_cves(scan_data: dict) -> dict:
    vulnerabilities_db = load_vulnerabilities_db()
    enriched = deepcopy(scan_data)

    for row in enriched.get("results", []):
        keyword = build_search_keyword(
            row.get("product", ""),
            row.get("version", ""),
            row.get("service", ""),
        )

        local_key = f"{row.get('product', '')} {row.get('version', '')}".strip()
        local_match = vulnerabilities_db.get(local_key)
        row["vulnerability"] = local_match

        nvd_items = lookup_cves(keyword) if keyword else []
        row["cve_findings"] = _merge_cve_findings(local_match, nvd_items)

        if row["cve_findings"]:
            top = next((f for f in row["cve_findings"] if "error" not in f), None)
            if top and not row["vulnerability"]:
                row["vulnerability"] = {
                    "cve": top.get("cve"),
                    "cvss": top.get("cvss"),
                    "severity": top.get("severity"),
                    "description": top.get("description"),
                }

    return enriched


def _log_phase(pipeline_log: list[dict], phase: str, status: str, message: str = "") -> None:
    entry: dict[str, Any] = {"phase": phase, "status": status}
    if message:
        entry["message"] = message
    pipeline_log.append(entry)


def run_full_scan(
    target: str,
    enrich_cve: bool = True,
    ai_analyze: bool = True,
    auto_exploit: bool = True,
) -> dict:
    pipeline_log: list[dict] = []
    scan_data: dict[str, Any] = {"target": target, "results": [], "os": []}

    try:
        scan_data = scan_target(target)
        _log_phase(pipeline_log, "nmap", "ok")
    except Exception as exc:
        _log_phase(pipeline_log, "nmap", "error", str(exc))
        return {"target": target, "error": str(exc), "pipeline_log": pipeline_log}

    if scan_data.get("error"):
        _log_phase(pipeline_log, "nmap", "error", scan_data["error"])
        scan_data["pipeline_log"] = pipeline_log
        return scan_data

    if enrich_cve:
        try:
            scan_data = enrich_scan_with_cves(scan_data)
            _log_phase(pipeline_log, "cve", "ok")
        except Exception as exc:
            _log_phase(pipeline_log, "cve", "error", str(exc))
            scan_data.setdefault("warnings", []).append(f"CVE/NVD: {exc}")

    exploitation: dict[str, Any] = {
        "attempts": [],
        "flag_captured": False,
        "flags": [],
        "playbook_steps": [],
    }

    if auto_exploit:
        try:
            exploitation = run_exploitation_checks(target, scan_data)
            scan_data["exploitation"] = exploitation
            if exploitation.get("flag_captured"):
                _log_phase(pipeline_log, "exploit", "ok", "Flag capturada")
            elif exploitation.get("attempts"):
                _log_phase(pipeline_log, "exploit", "partial", "FTP probado sin flag")
            else:
                _log_phase(pipeline_log, "exploit", "skipped", "Sin vectores automáticos")
        except Exception as exc:
            _log_phase(pipeline_log, "exploit", "error", str(exc))
            scan_data["exploitation"] = exploitation
            scan_data.setdefault("warnings", []).append(f"Explotación: {exc}")

    playbook = build_playbook_analysis(target, scan_data, exploitation)

    if ai_analyze:
        try:
            ai_result = suggest_attack_vectors(scan_data)
            scan_data["ai_analysis"] = merge_ai_with_playbook(ai_result, playbook, exploitation)
            if scan_data["ai_analysis"].get("enabled"):
                _log_phase(pipeline_log, "ai", "ok")
            else:
                _log_phase(
                    pipeline_log,
                    "ai",
                    "fallback",
                    scan_data["ai_analysis"].get("message", "Playbook usado"),
                )
        except Exception as exc:
            _log_phase(pipeline_log, "ai", "error", str(exc))
            scan_data["ai_analysis"] = playbook
            scan_data.setdefault("warnings", []).append(f"IA: {exc}")
    else:
        scan_data["ai_analysis"] = playbook
        _log_phase(pipeline_log, "ai", "skipped", "IA desactivada en petición")

    scan_data["pipeline_log"] = pipeline_log
    return scan_data
