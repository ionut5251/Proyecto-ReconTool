# Servicio informe Word

#recontool #backend #informe #word

Relacionado: [[API]] · [[../07-Futuro/Informe-Word-auditoria]] · [[Pipeline-de-escaneo]]

---

## Archivo

`code/backend/app/services/report_generator.py`

---

## Dependencia

```
python-docx>=1.1.0
```

Instalar en Kali:

```bash
./venv/bin/pip install -r requirements.txt
```

---

## Endpoint

### `POST /api/report`

Genera y descarga un `.docx`.

**Requisito:** `scan_data.exploitation.flag_captured === true`

**Body:**

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `scan_data` | object | JSON completo del scan |
| `auditor` | string | Opcional; default `REPORT_AUDITOR_NAME` en `.env` |

**Respuesta:** archivo Word (`Content-Disposition: attachment`)

**Error JSON:** si no hay flag o falla la generación.

---

## Datos usados del scan

| Sección informe | Origen en JSON |
|-----------------|----------------|
| Puertos | `results[]` |
| CVEs | `cve_findings[]` |
| Pasos FTP | `exploitation.attempts[].steps` |
| Flag | `exploitation.flags[]` |
| Pipeline | `pipeline_log[]` |
| IA | `ai_analysis.analysis` |

---

## Frontend

Botón en panel **Flag capturada** → `POST /api/report` → descarga automática.

Script: `code/frontend/js/results.js` → `downloadAuditReport()`.

---

## Enlaces

- [[Configuracion-env#Informe Word]]
- [[Servicio-FTP-exploit]]
