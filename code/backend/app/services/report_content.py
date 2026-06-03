"""Contenido compartido para informes Word y HTML."""

from __future__ import annotations

import re

from app.core.config import NMAP_ARGUMENTS


def safe_target(target: str) -> str:
    return re.sub(r"[^\w.\-]", "_", str(target))


def risk_level(scan_data: dict) -> str:
    if scan_data.get("exploitation", {}).get("flag_captured"):
        return "CRÍTICO"
    for row in scan_data.get("results", []):
        for finding in row.get("cve_findings") or []:
            sev = str(finding.get("severity", "")).upper()
            if sev in ("CRITICAL", "CRÍTICO", "HIGH", "ALTO"):
                return "CRÍTICO"
    if scan_data.get("results"):
        return "MEDIO"
    return "BAJO"


def target_display(scan_data: dict) -> str:
    """IP del objetivo y URLs web detectadas (sin nombres de máquina/lab)."""
    target = str(scan_data.get("target", "N/A"))
    parts = [target]
    osint = scan_data.get("osint") or {}
    for w in osint.get("web") or []:
        url = w.get("url")
        if url and w.get("status"):
            parts.append(url)
    return " · ".join(parts)


def ports_summary(scan_data: dict) -> str:
    parts = []
    for row in scan_data.get("results", []):
        if str(row.get("state", "")).lower() != "open":
            continue
        port = row.get("port")
        service = row.get("service", "?")
        product = row.get("product", "")
        version = row.get("version", "")
        detail = f"{port}/tcp — {service.upper()}"
        if product:
            detail += f" ({product} {version})".strip()
        parts.append(detail)
    return ", ".join(parts) if parts else "Sin puertos abiertos detectados"


def executive_summary(scan_data: dict) -> str:
    target_label = target_display(scan_data)
    ports = ports_summary(scan_data)
    flag_ok = scan_data.get("exploitation", {}).get("flag_captured")
    flags = scan_data.get("exploitation", {}).get("flags") or []

    intro = (
        f"La presente auditoría de seguridad ofensiva fue realizada sobre el objetivo "
        f"{target_label}, con el fin de identificar servicios expuestos, vulnerabilidades "
        f"asociadas y vectores de explotación en un entorno autorizado. "
        f"Servicios analizados: {ports}."
    )

    if flag_ok and flags:
        flag_content = flags[0].get("content", "")
        vector = (scan_data.get("exploitation") or {}).get("vector_used", "")
        if vector == "telnet_root_blank":
            vector_desc = "Telnet con usuario root y contraseña vacía"
        elif vector == "ftp_anonymous":
            vector_desc = "FTP con autenticación anónima"
        elif vector == "smb_anonymous":
            vector_desc = "SMB anónimo — enumeración de shares y lectura de flag"
        else:
            vector_desc = "explotación automática según servicios detectados"
        return (
            f"{intro}\n\n"
            f"Como resultado, se logró comprometer el objetivo obteniendo la flag: "
            f"{flag_content}. Vector principal: {vector_desc} "
            f"({flags[0].get('filename', 'flag.txt')})."
        )

    return (
        f"{intro}\n\n"
        "No se obtuvo flag en esta ejecución. Revise los vectores sugeridos y los pasos "
        "documentados en el desarrollo de la auditoría."
    )


def build_audit_steps(scan_data: dict) -> list[dict]:
    target = target_display(scan_data)
    steps: list[dict] = []

    ports_text = ports_summary(scan_data)
    os_lines = scan_data.get("os") or []
    os_text = "; ".join(f"{o.get('name')} ({o.get('accuracy')}%)" for o in os_lines) or "No determinado"

    steps.append(
        {
            "key": "nmap",
            "title": "Escaneo de puertos y servicios",
            "tool": f"nmap ({NMAP_ARGUMENTS})",
            "objective": f"Detectar puertos abiertos y fingerprint de servicios en {target}.",
            "findings": f"Puertos/servicios: {ports_text}. OS estimado: {os_text}.",
        }
    )

    osint = scan_data.get("osint") or {}
    if osint:
        osint_lines = []
        if osint.get("hostname"):
            osint_lines.append(f"Reverse DNS: {osint['hostname']}")
        for w in osint.get("web") or []:
            line = f"{w.get('url')}: HTTP {w.get('status') or '?'}"
            if w.get("title"):
                line += f" — {w['title']}"
            osint_lines.append(line)
        for note in osint.get("notes") or []:
            osint_lines.append(note)
        steps.append(
            {
                "key": "osint",
                "title": "OSINT pasivo",
                "tool": "reverse DNS + HTTP probe",
                "objective": "Superficie web y notas de recon sin explotación activa.",
                "findings": "\n".join(osint_lines) or "Sin datos OSINT adicionales.",
            }
        )

    cve_lines = []
    for row in scan_data.get("results", []):
        for f in row.get("cve_findings") or []:
            if "error" in f:
                continue
            cve_lines.append(
                f"Puerto {row.get('port')}: {f.get('cve')} ({f.get('severity')}, CVSS {f.get('cvss')})"
            )
    if cve_lines:
        steps.append(
            {
                "key": "cve",
                "title": "Correlación de vulnerabilidades (CVE)",
                "tool": "Base local + NVD API",
                "objective": "Identificar CVEs asociados a productos y versiones detectados.",
                "findings": "\n".join(cve_lines[:10]),
            }
        )

    exploitation = scan_data.get("exploitation") or {}
    for attempt in exploitation.get("attempts", []):
        module = attempt.get("module", "exploit")
        if module == "telnet_root_blank":
            title = "Explotación — Telnet (root / sin contraseña)"
            tool = "ReconTool telnet_probe / telnet"
            objective = "Acceso Telnet con usuario root y contraseña vacía."
        elif module == "smb_anonymous":
            title = "Explotación — SMB anónimo"
            tool = "ReconTool smb_probe / smbclient"
            objective = "Listar shares SMB, explorar carpetas y obtener flag.txt."
        else:
            title = "Explotación — FTP anónimo"
            tool = "ReconTool ftp_probe / FTP anonymous"
            objective = "FTP anónimo y lectura de flag.txt."

        step_details = "\n".join(
            f"[{s.get('action')}] {s.get('detail')}" for s in attempt.get("steps", [])
        )
        flags = attempt.get("flags") or []
        flag_text = ""
        if flags:
            flag_text = "\n".join(
                f"Flag obtenida ({f.get('filename')}): {f.get('content')}" for f in flags
            )
        findings = step_details
        if flag_text:
            findings += f"\n\n{flag_text}"

        steps.append(
            {
                "key": "exploit",
                "title": title,
                "tool": tool,
                "objective": objective,
                "findings": findings or attempt.get("error", "Sin resultados"),
            }
        )

    ai = scan_data.get("ai_analysis") or {}
    analysis = ai.get("analysis") or {}
    if analysis.get("summary"):
        vectors = analysis.get("vectors") or []
        vector_text = "\n".join(
            f"- {v.get('title')} ({v.get('priority')}): {v.get('rationale', '')[:200]}"
            for v in vectors[:5]
        )
        provider = ai.get("provider", "playbook")
        tool_label = provider if provider != "openai" else f"{provider} / {ai.get('model', '')}"
        steps.append(
            {
                "key": "ia",
                "title": "Análisis de vectores (IA / playbook)",
                "tool": tool_label,
                "objective": "Priorizar vectores de ataque y siguientes comprobaciones.",
                "findings": f"{analysis.get('summary')}\n{vector_text}".strip(),
            }
        )

    return steps
