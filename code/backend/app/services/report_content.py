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
    target = scan_data.get("target", "N/A")
    ports = ports_summary(scan_data)
    flag_ok = scan_data.get("exploitation", {}).get("flag_captured")
    flags = scan_data.get("exploitation", {}).get("flags") or []

    intro = (
        f"La presente auditoría de seguridad ofensiva fue realizada sobre el sistema "
        f"{target}, con el objetivo de identificar servicios expuestos, vulnerabilidades "
        f"asociadas y vectores de explotación en un entorno de laboratorio autorizado (HTB/práctica académica). "
        f"Servicios analizados: {ports}."
    )

    if flag_ok and flags:
        flag_content = flags[0].get("content", "")
        return (
            f"{intro}\n\n"
            f"Como resultado, se logró comprometer el objetivo obteniendo la flag de usuario: "
            f"{flag_content}. El vector principal fue FTP con autenticación anónima y lectura "
            f"del archivo {flags[0].get('filename', 'flag.txt')}."
        )

    return (
        f"{intro}\n\n"
        "No se obtuvo flag en esta ejecución. Revise los vectores sugeridos y los pasos "
        "documentados en el desarrollo de la auditoría."
    )


def build_audit_steps(scan_data: dict) -> list[dict]:
    target = scan_data.get("target", "N/A")
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
                "title": "Explotación — FTP anónimo",
                "tool": "ftplib (ReconTool) / FTP anonymous",
                "objective": (
                    "Comprobar acceso anónimo al servicio FTP, listar archivos "
                    "y descargar flag.txt si existe (vector HTB Fawn)."
                ),
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
        steps.append(
            {
                "key": "ia",
                "title": "Análisis de vectores (IA / playbook)",
                "tool": f"{ai.get('provider', 'N/A')} / {ai.get('model', 'N/A')}",
                "objective": "Priorizar vectores de ataque y siguientes comprobaciones.",
                "findings": f"{analysis.get('summary')}\n{vector_text}".strip(),
            }
        )

    return steps
