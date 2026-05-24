# Capturas automáticas por paso

#recontool #backend #evidencias #screenshots

Relacionado: [[Servicio-informe-Word]] · [[../07-Futuro/Informe-Word-auditoria]]

---

## Archivo

`code/backend/app/services/step_capture.py`

---

## Qué hace

Tras capturar una **flag**, ReconTool genera automáticamente PNG de evidencia por cada fase:

| Archivo | Paso |
|---------|------|
| `01_nmap.png` | Escaneo nmap |
| `02_cve.png` | CVEs (si aplica) |
| `03_exploit.png` | FTP / explotación |
| `04_ia.png` | Análisis IA (si aplica) |
| `99_flag.png` | Flag final |

Ubicación: `code/backend/data/screenshots/<IP>/`

Las imágenes imitan terminal (fondo oscuro, cabecera roja ReconTool) con el **texto real** del paso — no hace falta pantallazo manual.

---

## Cuándo se ejecuta

Al final de `run_full_scan()` si `flag_captured === true`.

Pipeline log: fase `evidence: ok`.

También se regeneran al descargar informe si faltaban.

---

## Dependencia

`Pillow` — incluido en `requirements.txt` ( `./recontool` lo instala).

---

## Informes

Las capturas se incrustan en:

- Word (`.docx`)
- HTML Linux (`.html`) — imágenes en base64 embebidas

---

## Futuro (v2)

Capturas reales del navegador (Playwright) además de las tarjetas terminal.

---

## Enlaces

- [[Servicio-informe-Word]]
- [[Pipeline-de-escaneo]]
