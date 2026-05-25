"""OSINT / recon pasivo ligero (web, DNS, subdominios)."""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services.service_router import _open_rows


def _reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _probe_http_url(url: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"url": url, "status": None, "title": None, "error": None}
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as client:
            resp = client.get(url)
            entry["status"] = resp.status_code
            text = resp.text[:8000]
            if "<title>" in text.lower():
                start = text.lower().index("<title>") + 7
                end = text.lower().find("</title>", start)
                if end > start:
                    entry["title"] = text[start:end].strip()[:200]
    except Exception as exc:
        entry["error"] = str(exc)
    return entry


def run_passive_osint(target: str, scan_data: dict) -> dict[str, Any]:
    hostname = _reverse_dns(target)
    web_entries: list[dict] = []
    subdomains: list[str] = []
    notes: list[str] = []

    for row in _open_rows(scan_data):
        port = int(row.get("port", 0))
        if port not in (80, 443, 8080, 8443, 8000, 8888):
            continue
        scheme = "https" if port in (443, 8443) else "http"
        if port in (80, 443):
            url = f"{scheme}://{target}"
        else:
            url = f"{scheme}://{target}:{port}"
        web_entries.append(_probe_http_url(url))

    if hostname and "." in hostname:
        parts = hostname.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
            notes.append(f"Dominio inferido (reverse DNS): {base_domain}")
            subdomains.append(hostname)
    else:
        notes.append(
            "Subdominios: objetivo por IP sin dominio público asociado. "
            "No aplica enumeración DNS de subdominios en este caso."
        )

    if not web_entries:
        notes.append("No se detectaron servicios HTTP/HTTPS abiertos en el escaneo.")

    has_web = any(w.get("status") for w in web_entries)

    return {
        "target": target,
        "hostname": hostname,
        "has_web": has_web,
        "web": web_entries,
        "subdomains": subdomains,
        "notes": notes,
        "sources": ["nmap", "reverse_dns", "http_probe"],
    }
