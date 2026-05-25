from copy import deepcopy
from typing import Any, Optional

from app.services.ai_advisor import suggest_attack_vectors
from app.services.cve_lookup import build_search_keyword, lookup_cves
from app.services.exploit_runner import run_exploitation_checks
from app.services.nmap_scanner import scan_target
from app.services.osint_passive import run_passive_osint
from app.services.playbook_advisor import build_playbook_analysis, merge_ai_with_playbook
from app.services.service_router import detect_attack_vectors
from app.services.step_capture import capture_all_evidence
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


def run_passive_recon(
    target: str,
    enrich_cve: bool = True,
    osint: bool = True,
) -> dict:
    """Fase 1: nmap + CVE + OSINT + plan de ataque (sin explotación)."""
    pipeline_log: list[dict] = []
    scan_data: dict[str, Any] = {
        "target": target,
        "phase": "passive",
        "results": [],
        "os": [],
    }

    try:
        scan_data = scan_target(target)
        _log_phase(pipeline_log, "nmap", "ok")
    except Exception as exc:
        _log_phase(pipeline_log, "nmap", "error", str(exc))
        return {"target": target, "error": str(exc), "pipeline_log": pipeline_log, "phase": "passive"}

    if scan_data.get("error"):
        scan_data["pipeline_log"] = pipeline_log
        scan_data["phase"] = "passive"
        return scan_data

    if enrich_cve:
        try:
            scan_data = enrich_scan_with_cves(scan_data)
            _log_phase(pipeline_log, "cve", "ok")
        except Exception as exc:
            _log_phase(pipeline_log, "cve", "error", str(exc))
            scan_data.setdefault("warnings", []).append(f"CVE/NVD: {exc}")

    if osint:
        try:
            scan_data["osint"] = run_passive_osint(target, scan_data)
            _log_phase(pipeline_log, "osint", "ok")
        except Exception as exc:
            _log_phase(pipeline_log, "osint", "error", str(exc))
            scan_data["osint"] = {"notes": [str(exc)]}

    scan_data["attack_plan"] = detect_attack_vectors(scan_data)
    _log_phase(
        pipeline_log,
        "attack_plan",
        "ok",
        scan_data["attack_plan"].get("message", ""),
    )

    scan_data["ai_analysis"] = build_playbook_analysis(
        target,
        scan_data,
        {"flag_captured": False, "attempts": []},
    )

    scan_data["exploitation"] = {
        "attempts": [],
        "flag_captured": False,
        "flags": [],
        "pending": True,
    }

    scan_data["pipeline_log"] = pipeline_log
    return scan_data


def run_active_attack(
    scan_data: dict,
    ai_analyze: bool = True,
) -> dict:
    """Fase 2: explotación según vector detectado + IA opcional."""
    target = scan_data.get("target", "unknown")
    pipeline_log = list(scan_data.get("pipeline_log", []))

    exploitation: dict[str, Any] = {
        "attempts": [],
        "flag_captured": False,
        "flags": [],
        "playbook_steps": [],
        "pending": False,
    }

    try:
        exploitation = run_exploitation_checks(target, scan_data)
        scan_data["exploitation"] = exploitation
        if exploitation.get("flag_captured"):
            _log_phase(pipeline_log, "exploit", "ok", exploitation.get("message", "Flag capturada"))
        elif exploitation.get("attempts"):
            _log_phase(pipeline_log, "exploit", "partial", exploitation.get("message", ""))
        else:
            _log_phase(pipeline_log, "exploit", "skipped", exploitation.get("message", "Sin vector"))
    except Exception as exc:
        _log_phase(pipeline_log, "exploit", "error", str(exc))
        scan_data["exploitation"] = exploitation
        scan_data.setdefault("warnings", []).append(f"Explotación: {exc}")

    playbook = build_playbook_analysis(target, scan_data, scan_data.get("exploitation", {}))

    if ai_analyze:
        try:
            ai_result = suggest_attack_vectors(scan_data)
            scan_data["ai_analysis"] = merge_ai_with_playbook(
                ai_result, playbook, scan_data.get("exploitation", {})
            )
            if scan_data["ai_analysis"].get("enabled"):
                _log_phase(pipeline_log, "ai", "ok")
            else:
                _log_phase(pipeline_log, "ai", "fallback", "Playbook")
        except Exception as exc:
            _log_phase(pipeline_log, "ai", "error", str(exc))
            scan_data["ai_analysis"] = playbook
    else:
        scan_data["ai_analysis"] = playbook

    scan_data["phase"] = "active"
    scan_data["pipeline_log"] = pipeline_log

    if scan_data.get("exploitation", {}).get("flag_captured"):
        try:
            capture_all_evidence(scan_data)
            _log_phase(pipeline_log, "evidence", "ok", "Capturas generadas")
        except Exception as exc:
            _log_phase(pipeline_log, "evidence", "error", str(exc))

    return scan_data


def run_full_scan(
    target: str,
    enrich_cve: bool = True,
    ai_analyze: bool = True,
    auto_exploit: bool = True,
) -> dict:
    """Pipeline completo (compatibilidad)."""
    data = run_passive_recon(target, enrich_cve=enrich_cve)
    if data.get("error"):
        return data
    if auto_exploit:
        return run_active_attack(data, ai_analyze=ai_analyze)
    return data
