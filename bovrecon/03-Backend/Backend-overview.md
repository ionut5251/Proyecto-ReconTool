# Backend — Visión general

#recontool #backend

Relacionado: [[API]] · [[Pipeline-de-escaneo]] · [[Configuracion-env]] · [[../02-Arquitectura/Arquitectura-general]]

---

## Stack

| Tecnología | Versión / nota |
|------------|----------------|
| Python | 3.10+ recomendado |
| FastAPI | API REST + validación |
| Uvicorn | ASGI server (`run.py`) |
| python-nmap | Wrapper de nmap |
| httpx | Cliente HTTP (NVD, OpenAI, Ollama) |
| python-dotenv | Variables `.env` |
| Pydantic v2 | Schemas en `app/models/schemas.py` |

---

## Módulos

| Archivo | Función |
|---------|---------|
| `app/main.py` | Crea app, CORS, router `/api`, sirve frontend |
| `app/api/routes.py` | Endpoints HTTP |
| `app/core/config.py` | Constantes y env |
| `app/models/schemas.py` | `ScanRequest`, `AnalyzeRequest` |
| `app/services/nmap_scanner.py` | Escaneo nmap |
| `app/services/vuln_db.py` | Carga JSON local |
| `app/services/cve_lookup.py` | API NVD |
| `app/services/scan_pipeline.py` | Orquestación |
| `app/services/ai_advisor.py` | LLM vectores |

---

## Arranque

Desde `code/backend/`:

```bash
python run.py
```

Equivalente: `uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload`

---

## Variables críticas

Ver [[Configuracion-env]] y archivo `code/backend/.env.example`.

---

## Enlaces detallados

- [[Servicio-nmap]]
- [[Servicio-CVE-NVD]]
- [[Servicio-IA]]
- [[Pipeline-de-escaneo]]
- [[API]]
