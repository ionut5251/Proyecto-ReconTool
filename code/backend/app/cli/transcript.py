"""Transcripción de sesión en Markdown.

Complementa al informe .docx: deja constancia, en texto plano, de los comandos
que ReconTool fue lanzando y de la información obtenida. Formato agnóstico,
fácil de pegar en la memoria del máster o de versionar.
"""

from __future__ import annotations

from datetime import datetime

from app.services.report_content import (
    build_audit_steps,
    executive_summary,
    ports_summary,
    risk_level,
)


def build_transcript(session, auditor: str = "") -> str:
    scan_data = session.scan_data
    target = scan_data.get("target", session.target)
    now = datetime.now().strftime("%d/%m/%Y %H:%M")

    lines: list[str] = []
    lines.append(f"# Transcripción de auditoría — {target}")
    lines.append("")
    lines.append(f"- **Fecha:** {now}")
    if auditor:
        lines.append(f"- **Auditor:** {auditor}")
    lines.append(f"- **Nivel de riesgo estimado:** {risk_level(scan_data)}")
    lines.append(f"- **Puertos:** {ports_summary(scan_data)}")
    lines.append(f"- **Duración de la sesión:** {session.elapsed():.0f} s")
    lines.append("")
    lines.append("> Sesión efímera: los datos intermedios se han borrado al cerrar.")
    lines.append("")

    lines.append("## Resumen ejecutivo")
    lines.append("")
    lines.append(executive_summary(scan_data))
    lines.append("")

    lines.append("## Comandos ejecutados")
    lines.append("")
    if session.commands:
        lines.append("```bash")
        for entry in session.commands:
            note = f"   # {entry['note']}" if entry.get("note") else ""
            lines.append(f"{entry['command']}{note}")
        lines.append("```")
    else:
        lines.append("_No se registraron comandos._")
    lines.append("")

    lines.append("## Desarrollo paso a paso")
    lines.append("")
    for idx, step in enumerate(build_audit_steps(scan_data), start=1):
        lines.append(f"### Paso {idx} — {step['title']}")
        lines.append("")
        lines.append(f"- **Herramienta:** {step['tool']}")
        lines.append(f"- **Objetivo:** {step['objective']}")
        lines.append("- **Hallazgos:**")
        lines.append("")
        lines.append("```")
        lines.append(step["findings"].strip() or "(sin datos)")
        lines.append("```")
        lines.append("")

    web = scan_data.get("web_enum")
    if web:
        lines.append("## Enumeración web")
        lines.append("")
        lines.append(f"- **Base:** {web.get('base')}  ·  **Herramienta:** {web.get('tool')}")
        hits = web.get("hits") or []
        if hits:
            lines.append(f"- **Rutas encontradas ({len(hits)}):**")
            lines.append("")
            lines.append("```")
            for h in hits[:60]:
                lines.append(f"/{h['path']}  (HTTP {h['status']}, {h['size']} bytes)")
            lines.append("```")
        if web.get("interesting"):
            lines.append(f"- **Interesantes:** {', '.join('/' + p for p in web['interesting'])}")
        lr = web.get("login_result")
        if web.get("login"):
            lines.append(f"- **Login:** {web.get('login')}")
        if lr and lr.get("success"):
            lines.append(f"- **Credenciales válidas:** `{lr.get('user')} : {lr.get('password')}` ({lr.get('evidence','')})")
        lines.append("")

    flags = scan_data.get("exploitation", {}).get("flags") or []
    if flags:
        lines.append("## Flags obtenidas")
        lines.append("")
        for f in flags:
            lines.append(f"- `{f.get('filename')}`: **{f.get('content')}**")
        lines.append("")

    lines.append("---")
    lines.append("_Generado por ReconTool CLI — uso exclusivo en entornos autorizados._")
    lines.append("")
    return "\n".join(lines)
