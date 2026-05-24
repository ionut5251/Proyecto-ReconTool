# Servicio informe Word / HTML

#recontool #backend #informe #word #html

Relacionado: [[API]] · [[Servicio-capturas-automaticas]] · [[../07-Futuro/Informe-Word-auditoria]]

---

## Archivos

| Archivo | Formato |
|---------|---------|
| `report_generator.py` | Word `.docx` |
| `report_html.py` | HTML (Linux/Kali) |
| `report_content.py` | Contenido compartido |
| `step_capture.py` | Capturas PNG automáticas |

---

## Endpoint

### `POST /api/report`

| Campo | Valores |
|-------|---------|
| `scan_data` | JSON del scan |
| `format` | `docx` (default) o `html` |
| `auditor` | Opcional |

**Requisito:** flag capturada.

---

## Informe HTML (Kali)

- Un solo archivo `.html`
- Estilo oscuro tipo informe pentest
- Imágenes embebidas en base64 (capturas automáticas)
- Abrir con Firefox — ideal para lab sin Windows

---

## Informe Word

Misma estructura que el ejemplo académico + figuras por paso.

---

## Capturas

Generadas automáticamente — [[Servicio-capturas-automaticas]].

---

## Frontend

Dos botones en panel **Flag capturada**:

- `Informe Word (.docx)`
- `Informe Linux (HTML)`

---

## Enlaces

- [[Configuracion-env#Informe Word]]
- [[Servicio-FTP-exploit]]
