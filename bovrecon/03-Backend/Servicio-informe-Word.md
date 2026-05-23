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

## Capturas / evidencias gráficas

Carpeta: `code/backend/data/screenshots/<IP>/`

| Archivo | Paso |
|---------|------|
| `01_nmap.png` | Escaneo / puertos |
| `02_cve.png` | CVEs |
| `03_exploit.png` | Explotación FTP |
| `04_ia.png` | Panel IA |
| `99_flag.png` | Flag final |

Si existe el PNG, se incrusta en el Word. Si no, placeholder indicando qué añadir.

**v2 (segunda entrega):** capturas automáticas — [[../07-Futuro/Informe-Word-auditoria]].

---

## Enlaces

- [[Configuracion-env#Informe Word]]
- [[Servicio-FTP-exploit]]
