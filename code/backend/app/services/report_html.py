"""Informe de auditoría en HTML (ideal para Kali / Linux)."""

from __future__ import annotations

import base64
import html
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core.config import NMAP_ARGUMENTS, REPORT_AUDITOR_NAME, SCREENSHOTS_DIR
from app.services.report_content import (
    build_audit_steps,
    executive_summary,
    ports_summary,
    risk_level,
    safe_target,
)
from app.services.step_capture import capture_all_evidence


def _find_screenshot(target: str, step_num: int, step_key: str) -> Optional[Path]:
    base = SCREENSHOTS_DIR / safe_target(target)
    if not base.is_dir():
        return None
    exts = (".png", ".jpg", ".jpeg", ".webp")
    patterns = [f"{step_num:02d}_{step_key}", f"{step_num:02d}", step_key]
    if step_key == "flag":
        patterns.append("99_flag")
    for pattern in patterns:
        for ext in exts:
            path = base / f"{pattern}{ext}"
            if path.is_file():
                return path
    return None


def _img_tag(target: str, step_num: int, step_key: str, caption: str) -> str:
    path = _find_screenshot(target, step_num, step_key)
    if not path:
        return f'<p class="missing">[Captura no disponible: {step_num:02d}_{step_key}.png]</p>'
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return (
        f'<figure class="evidence">'
        f'<img src="data:image/png;base64,{b64}" alt="{html.escape(caption)}" />'
        f'<figcaption>Figura {step_num}: {html.escape(caption)}</figcaption>'
        f"</figure>"
    )


def generate_audit_report_html(scan_data: dict, auditor: str | None = None) -> str:
    if not scan_data.get("evidence_screenshots"):
        capture_all_evidence(scan_data)

    target = scan_data.get("target", "objetivo")
    auditor = auditor or REPORT_AUDITOR_NAME
    now = datetime.now()
    date_str = now.strftime("%d / %m / %Y")
    risk = risk_level(scan_data)
    summary = executive_summary(scan_data)
    steps = build_audit_steps(scan_data)

    steps_html = ""
    for idx, step in enumerate(steps, start=1):
        key = step.get("key", f"step{idx}")
        steps_html += f"""
        <section class="step">
          <h2>Paso {idx} — {html.escape(step['title'])}</h2>
          <p><strong>Herramienta:</strong> {html.escape(step['tool'])}</p>
          <p><strong>Objetivo:</strong> {html.escape(step['objective'])}</p>
          <p><strong>Hallazgos:</strong></p>
          <pre>{html.escape(step['findings'])}</pre>
          {_img_tag(target, idx, key, step['title'])}
        </section>
        """

    pipeline = scan_data.get("pipeline_log") or []
    pipeline_html = "".join(
        f"<li>{html.escape(e.get('phase', ''))}: {html.escape(e.get('status', ''))}"
        f"{' — ' + html.escape(e.get('message', '')) if e.get('message') else ''}</li>"
        for e in pipeline
    )

    flags = scan_data.get("exploitation", {}).get("flags") or []
    flags_html = ""
    for f in flags:
        flags_html += f"<p><strong>{html.escape(f.get('filename', ''))}</strong></p>"
        flags_html += f'<pre class="flag">{html.escape(f.get("content", ""))}</pre>'
    if flags:
        flags_html += _img_tag(target, 99, "flag", "Flag capturada — evidencia final")

    recs = [
        "Deshabilitar login anónimo en FTP o restringir permisos.",
        "No almacenar flags ni credenciales en directorios accesibles.",
        "Actualizar servicios y monitorizar CVEs.",
    ]
    if scan_data.get("exploitation", {}).get("flag_captured"):
        recs.insert(0, "URGENTE: Corregir misconfiguración FTP que permitió leer flag.txt.")

    recs_html = "".join(f"<li>{html.escape(r)}</li>" for r in recs)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Informe Pentest — {html.escape(target)}</title>
  <style>
    body {{ font-family: Calibri, 'Segoe UI', sans-serif; background: #111; color: #eee; margin: 0; padding: 2rem; line-height: 1.5; }}
    .cover {{ text-align: center; border-bottom: 2px solid #d0021b; padding-bottom: 2rem; margin-bottom: 2rem; }}
    h1 {{ color: #d0021b; }}
    h2 {{ color: #ccc; border-left: 4px solid #d0021b; padding-left: 0.75rem; }}
    .meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; max-width: 720px; margin: 2rem auto; text-align: left; }}
    .meta div {{ background: #1a1a1a; padding: 1rem; border-radius: 4px; }}
    .step {{ background: #1a1a1a; padding: 1.25rem; margin: 1.5rem 0; border-radius: 6px; }}
    pre {{ background: #000; padding: 1rem; overflow-x: auto; font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 0.9rem; }}
    pre.flag {{ color: #3ddc84; font-size: 1.1rem; border: 1px solid #3ddc84; }}
    .evidence img {{ max-width: 100%; border: 1px solid #444; border-radius: 4px; }}
    figcaption {{ font-size: 0.85rem; color: #999; margin-top: 0.5rem; }}
    .missing {{ color: #c90; font-style: italic; }}
    ul {{ padding-left: 1.25rem; }}
    .footer {{ text-align: center; margin-top: 3rem; color: #666; font-size: 0.85rem; }}
    @media print {{ body {{ background: #fff; color: #000; }} .step {{ background: #f5f5f5; }} }}
  </style>
</head>
<body>
  <div class="cover">
    <p style="color:#888;">CONFIDENCIAL · USO RESTRINGIDO</p>
    <h1>INFORME TÉCNICO</h1>
    <h2 style="border:none;padding:0;">AUDITORÍA DE SEGURIDAD OFENSIVA</h2>
    <div class="meta">
      <div><strong>Objetivo</strong><br>{html.escape(target)}</div>
      <div><strong>Fecha</strong><br>{html.escape(date_str)}</div>
      <div><strong>Puertos</strong><br>{html.escape(ports_summary(scan_data))}</div>
      <div><strong>Riesgo</strong><br>{html.escape(risk)}</div>
      <div><strong>Auditor</strong><br>{html.escape(auditor)}</div>
      <div><strong>Herramienta</strong><br>ReconTool v1.0</div>
    </div>
  </div>

  <section>
    <h2>1. Resumen ejecutivo</h2>
    <p>{html.escape(summary).replace(chr(10), '<br/>')}</p>
  </section>

  <section>
    <h2>2. Metodología</h2>
    <p>PTES / OWASP — nmap, CVE (NVD), explotación controlada, análisis IA/playbook.</p>
    <p><code>{html.escape(NMAP_ARGUMENTS)}</code></p>
  </section>

  <section>
    <h2>3. Desarrollo de la auditoría</h2>
    <p>Evidencias generadas automáticamente por ReconTool en cada fase del pipeline.</p>
    {steps_html}
    <h3>Cronología</h3>
    <ul>{pipeline_html}</ul>
  </section>

  <section>
    <h2>4. Recomendaciones</h2>
    <ul>{recs_html}</ul>
  </section>

  <section>
    <h2>5. Flag obtenida</h2>
    {flags_html or '<p>No capturada.</p>'}
  </section>

  <p class="footer">— FIN DEL INFORME — · ReconTool · {now.year}</p>
</body>
</html>
"""
