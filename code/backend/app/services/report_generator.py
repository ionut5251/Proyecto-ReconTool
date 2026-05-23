"""Generación de informe de auditoría pentest en formato Word (.docx)."""

from __future__ import annotations

import io
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

from app.core.config import NMAP_ARGUMENTS, REPORT_AUDITOR_NAME, SCREENSHOTS_DIR


def _risk_level(scan_data: dict) -> str:
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


def _ports_summary(scan_data: dict) -> str:
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


def _safe_target(target: str) -> str:
    return re.sub(r"[^\w.\-]", "_", str(target))


def _find_screenshot(target: str, step_num: int, step_key: str) -> Optional[Path]:
    base = SCREENSHOTS_DIR / _safe_target(target)
    if not base.is_dir():
        return None

    exts = (".png", ".jpg", ".jpeg", ".webp")
    patterns = [f"{step_num:02d}_{step_key}", f"{step_num:02d}", step_key, "flag" if step_key == "flag" else ""]

    for pattern in patterns:
        if not pattern:
            continue
        for ext in exts:
            path = base / f"{pattern}{ext}"
            if path.is_file():
                return path
    return None


def _add_evidence_block(
    doc: Document,
    target: str,
    step_num: int,
    step_key: str,
    caption: str,
) -> None:
    doc.add_paragraph()
    p = doc.add_paragraph()
    p.add_run("Evidencia gráfica\n").bold = True

    image_path = _find_screenshot(target, step_num, step_key)
    if image_path:
        doc.add_picture(str(image_path), width=Inches(5.5))
        cap = doc.add_paragraph(f"Figura {step_num}: {caption}")
        cap.runs[0].italic = True
        cap.runs[0].font.size = Pt(9)
        return

    folder = f"data/screenshots/{_safe_target(target)}/"
    placeholder = doc.add_paragraph(
        f"[Captura pendiente — añadir {folder}{step_num:02d}_{step_key}.png "
        f"(pantallazo del paso: {caption})]"
    )
    placeholder.runs[0].italic = True
    placeholder.runs[0].font.color.rgb = RGBColor(0x99, 0x66, 0x00)


def _add_label_value(doc: Document, label: str, value: str) -> None:
    p = doc.add_paragraph()
    run_label = p.add_run(f"{label}\n")
    run_label.bold = True
    run_label.font.size = Pt(11)
    p.add_run(value).font.size = Pt(11)


def _add_step_block(
    doc: Document,
    step_num: int,
    title: str,
    tool: str,
    objective: str,
    findings: str,
    target: str,
    step_key: str,
) -> None:
    doc.add_heading(f"Paso {step_num}  —  {title}", level=2)
    _add_label_value(doc, "Herramienta", tool)
    _add_label_value(doc, "Objetivo", objective)
    _add_label_value(doc, "Hallazgos / Resultado", findings)
    _add_evidence_block(doc, target, step_num, step_key, title)
    doc.add_paragraph()


def _build_audit_steps(scan_data: dict) -> list[dict]:
    target = scan_data.get("target", "N/A")
    steps: list[dict] = []
    step_num = 1

    ports_text = _ports_summary(scan_data)
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
    step_num += 1

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
        step_num += 1

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
        step_num += 1

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


def _executive_summary(scan_data: dict) -> str:
    target = scan_data.get("target", "N/A")
    ports = _ports_summary(scan_data)
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


def generate_audit_report(
    scan_data: dict,
    auditor: Optional[str] = None,
) -> bytes:
    target = scan_data.get("target", "objetivo")
    auditor = auditor or REPORT_AUDITOR_NAME
    now = datetime.now()
    date_str = now.strftime("%d / %m / %Y")
    risk = _risk_level(scan_data)

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    # --- Portada ---
    p_conf = doc.add_paragraph("CONFIDENCIAL  ·  USO RESTRINGIDO")
    p_conf.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_conf.runs[0].font.size = Pt(9)
    p_conf.runs[0].font.color.rgb = RGBColor(0x99, 0x99, 0x99)

    t1 = doc.add_heading("INFORME TÉCNICO", level=0)
    t1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t2 = doc.add_heading("AUDITORÍA DE SEGURIDAD OFENSIVA", level=1)
    t2.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph()
    _add_label_value(doc, "Objetivo", target)
    _add_label_value(doc, "Puertos analizados", _ports_summary(scan_data))
    _add_label_value(doc, "Fecha de auditoría", date_str)
    _add_label_value(doc, "Nivel de riesgo", risk)
    _add_label_value(doc, "Clasificación", "CONFIDENCIAL — LABORATORIO AUTORIZADO")
    _add_label_value(doc, "Auditor", auditor)

    doc.add_paragraph()
    disclaimer = doc.add_paragraph(
        "Este documento contiene información sensible de uso exclusivamente académico/interno. "
        "Generado automáticamente por ReconTool. Solo válido para entornos con autorización explícita (HTB, VMs propias)."
    )
    disclaimer.runs[0].font.size = Pt(9)
    disclaimer.runs[0].italic = True

    footer = doc.add_paragraph(f"ReconTool Pentesting Report · v1.0 · {now.year}")
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.runs[0].font.size = Pt(9)

    doc.add_page_break()

    # --- Índice simplificado ---
    doc.add_heading("ÍNDICE", level=1)
    for item in [
        "1. Resumen Ejecutivo",
        "2. Metodología y Alcance",
        "3. Desarrollo de la Auditoría",
        "4. Resumen de Vulnerabilidades",
        "5. Recomendaciones",
        "6. Resultado — Flag obtenida",
    ]:
        doc.add_paragraph(item, style="List Bullet")

    doc.add_page_break()

    # --- 1. Resumen ejecutivo ---
    doc.add_heading("1. Resumen Ejecutivo", level=1)
    doc.add_paragraph(_executive_summary(scan_data))

    # --- 2. Metodología ---
    doc.add_heading("2. Metodología y Alcance", level=1)
    doc.add_paragraph(
        "Metodología basada en PTES y prácticas OWASP: reconocimiento, enumeración, "
        "correlación de vulnerabilidades y explotación controlada en lab."
    )
    table = doc.add_table(rows=5, cols=3)
    table.style = "Table Grid"
    headers = ["#", "FASE", "HERRAMIENTAS"]
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h
    rows_data = [
        ("1", "Reconocimiento", f"nmap ({NMAP_ARGUMENTS})"),
        ("2", "Correlación CVE", "Base local + NVD API"),
        ("3", "Explotación", "ReconTool ftp_probe (FTP anónimo)"),
        ("4", "Análisis", "IA / playbook ReconTool"),
    ]
    for idx, (num, phase, tools) in enumerate(rows_data, start=1):
        table.rows[idx].cells[0].text = num
        table.rows[idx].cells[1].text = phase
        table.rows[idx].cells[2].text = tools

    doc.add_paragraph()

    # --- 3. Desarrollo ---
    doc.add_heading("3. Desarrollo de la Auditoría", level=1)
    doc.add_paragraph(
        "Detalle paso a paso con evidencias gráficas. Coloque capturas en "
        f"data/screenshots/{_safe_target(target)}/ (ver documentación bovrecon)."
    )

    audit_steps = _build_audit_steps(scan_data)
    for idx, step in enumerate(audit_steps, start=1):
        _add_step_block(
            doc,
            idx,
            step["title"],
            step["tool"],
            step["objective"],
            step["findings"],
            target,
            step.get("key", f"step{idx}"),
        )

    # Pipeline log
    pipeline = scan_data.get("pipeline_log") or []
    if pipeline:
        doc.add_heading("Cronología del pipeline", level=2)
        for entry in pipeline:
            msg = entry.get("message", "")
            line = f"{entry.get('phase')}: {entry.get('status')}"
            if msg:
                line += f" — {msg}"
            doc.add_paragraph(line, style="List Bullet")

    # --- 4. Vulnerabilidades ---
    doc.add_heading("4. Resumen de Vulnerabilidades", level=1)
    vuln_table = doc.add_table(rows=1, cols=4)
    vuln_table.style = "Table Grid"
    for i, h in enumerate(["ID", "VULNERABILIDAD", "SEVERIDAD", "CVSS"]):
        vuln_table.rows[0].cells[i].text = h

    vid = 1
    seen: set[str] = set()
    for row in scan_data.get("results", []):
        for f in row.get("cve_findings") or []:
            if "error" in f:
                continue
            cve = f.get("cve", "")
            if not cve or cve in seen:
                continue
            seen.add(cve)
            r = vuln_table.add_row().cells
            r[0].text = f"V-{vid:02d}"
            r[1].text = f"{f.get('description', cve)[:120]}"
            r[2].text = str(f.get("severity", "—"))
            r[3].text = str(f.get("cvss", "—"))
            vid += 1

    if exploitation := scan_data.get("exploitation"):
        if exploitation.get("flag_captured"):
            r = vuln_table.add_row().cells
            r[0].text = f"V-{vid:02d}"
            r[1].text = "FTP anónimo con lectura de archivos sensibles (flag.txt)"
            r[2].text = "CRÍTICO"
            r[3].text = "9.1"

    if vid == 1:
        doc.add_paragraph("No se registraron CVEs críticos en esta ejecución.")

    # --- 5. Recomendaciones ---
    doc.add_heading("5. Recomendaciones", level=1)
    recs = [
        "Deshabilitar login anónimo en FTP o restringir permisos de solo lectura a directorios no sensibles.",
        "No almacenar flags, credenciales ni backups en directorios accesibles por FTP anónimo.",
        "Mantener servicios actualizados y monitorizar CVEs asociados a versiones detectadas.",
        "Aplicar hardening según CIS Benchmark para el sistema operativo y servicios expuestos.",
    ]
    if scan_data.get("exploitation", {}).get("flag_captured"):
        recs.insert(
            0,
            "URGENTE: Corregir misconfiguración FTP que permitió la exfiltración de flag.txt sin autenticación.",
        )
    for rec in recs:
        doc.add_paragraph(rec, style="List Bullet")

    # --- 6. Flag ---
    doc.add_heading("6. Resultado — Flag obtenida", level=1)
    flags = scan_data.get("exploitation", {}).get("flags") or []
    if flags:
        for f in flags:
            p = doc.add_paragraph()
            p.add_run(f"Archivo: {f.get('filename')}\n").bold = True
            run_flag = p.add_run(f.get("content", ""))
            run_flag.font.name = "Consolas"
            run_flag.font.size = Pt(12)
            run_flag.font.color.rgb = RGBColor(0x00, 0x66, 0x00)
        _add_evidence_block(doc, target, 99, "flag", "Flag obtenida — captura final")
    else:
        doc.add_paragraph("No se capturó flag en esta ejecución.")

    doc.add_paragraph()
    end = doc.add_paragraph("— FIN DEL INFORME —")
    end.alignment = WD_ALIGN_PARAGRAPH.CENTER
    end.runs[0].bold = True

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer.getvalue()
