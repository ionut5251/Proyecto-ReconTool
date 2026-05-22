import time
from typing import Optional

import httpx

from app.core.config import (
    NVD_API_KEY,
    NVD_API_URL,
    NVD_REQUEST_DELAY_SEC,
    NVD_RESULTS_PER_QUERY,
)

_cache: dict[str, list[dict]] = {}
_last_request_at: float = 0.0


def _throttle() -> None:
    global _last_request_at
    if NVD_API_KEY:
        return
    elapsed = time.monotonic() - _last_request_at
    if elapsed < NVD_REQUEST_DELAY_SEC:
        time.sleep(NVD_REQUEST_DELAY_SEC - elapsed)


def _extract_cvss(metrics: dict) -> tuple[Optional[float], Optional[str]]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or cvss_data.get("severity")
        return score, severity
    return None, None


def _parse_nvd_item(item: dict) -> Optional[dict]:
    cve_block = item.get("cve", {})
    cve_id = cve_block.get("id")
    if not cve_id:
        return None

    description = ""
    for entry in cve_block.get("descriptions", []):
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break
    if not description and cve_block.get("descriptions"):
        description = cve_block["descriptions"][0].get("value", "")

    cvss, severity = _extract_cvss(cve_block.get("metrics", {}))

    return {
        "cve": cve_id,
        "cvss": cvss,
        "severity": severity or "Unknown",
        "description": description[:400],
        "source": "nvd",
    }


def lookup_cves(keyword: str) -> list[dict]:
    keyword = keyword.strip()
    if len(keyword) < 3:
        return []

    if keyword in _cache:
        return _cache[keyword]

    _throttle()

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": NVD_RESULTS_PER_QUERY,
    }

    global _last_request_at
    _last_request_at = time.monotonic()

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        _cache[keyword] = []
        return [{"error": f"NVD lookup failed: {exc}", "source": "nvd"}]

    findings = []
    for item in payload.get("vulnerabilities", []):
        parsed = _parse_nvd_item(item)
        if parsed:
            findings.append(parsed)

    _cache[keyword] = findings
    return findings


def build_search_keyword(product: str, version: str, service: str) -> str:
    if product and version:
        return f"{product} {version}".strip()
    if product:
        return product.strip()
    if service:
        return service.strip()
    return ""
