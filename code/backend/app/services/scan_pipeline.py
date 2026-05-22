from copy import deepcopy
from typing import Optional

from app.services.ai_advisor import suggest_attack_vectors
from app.services.cve_lookup import build_search_keyword, lookup_cves
from app.services.nmap_scanner import scan_target
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


def run_full_scan(target: str, enrich_cve: bool = True, ai_analyze: bool = True) -> dict:
    scan_data = scan_target(target)

    if scan_data.get("error"):
        return scan_data

    if enrich_cve:
        scan_data = enrich_scan_with_cves(scan_data)

    if ai_analyze:
        scan_data["ai_analysis"] = suggest_attack_vectors(scan_data)
    else:
        scan_data["ai_analysis"] = {"enabled": False, "message": "Análisis IA desactivado en la petición."}

    return scan_data
