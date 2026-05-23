# API REST

#recontool #backend #api

Relacionado: [[Backend-overview]] · [[../02-Arquitectura/Flujo-de-datos]] · [[Pipeline-de-escaneo]]

---

## Base URL

`http://127.0.0.1:8000/api`

---

## Endpoints

### `GET /api/`

Health check.

**Respuesta ejemplo:**

```json
{
  "message": "ReconTool API running",
  "features": ["nmap_scan", "nvd_cve_lookup", "ai_attack_vectors"]
}
```

---

### `POST /api/scan`

Escaneo completo (nmap + CVE + IA opcional).

**Body (JSON):**

| Campo | Tipo | Default | Descripción |
|-------|------|---------|-------------|
| `target` | string | *requerido* | IP o hostname |
| `enrich_cve` | bool | `true` | Consultar NVD + base local |
| `ai_analyze` | bool | `true` | Llamar al LLM |

**Ejemplo curl:**

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"target\": \"scanme.nmap.org\", \"enrich_cve\": true, \"ai_analyze\": true}"
```

**Errores:** Devuelve `{ "error": "..." }` en excepciones (nmap no instalado, permisos, target inválido).

**Tiempo:** Puede ser **varios minutos** (nmap + NVD throttling + IA).

---

### `POST /api/enrich`

Añade `cve_findings` a un resultado de scan existente.

**Body:**

```json
{
  "scan_data": { "target": "...", "results": [], "os": [] }
}
```

Implementación: `enrich_scan_with_cves()` en `scan_pipeline.py`.

---

### `POST /api/report`

Genera informe de auditoría Word (.docx). **Solo si hay flag capturada.**

**Body:**

```json
{
  "scan_data": { "...": "resultado completo de /api/scan" },
  "auditor": "Tu Nombre (opcional)"
}
```

**Respuesta:** archivo `informe_pentest_{IP}_{fecha}.docx`

Ver [[Servicio-informe-Word]].

---

### `POST /api/analyze`

Solo análisis IA sobre datos ya escaneados.

**Body:** Igual que `/enrich`.

**Respuesta:**

```json
{ "ai_analysis": { "enabled": true, "provider": "...", "analysis": { ... } } }
```

---

## Códigos HTTP

Actualmente la API devuelve **200** incluso con `{ "error": ... }` en el body (patrón fail-in-body). Mejora futura: 4xx/5xx HTTP reales.

---

## CORS

Configurado en `app/main.py` con `allow_origins=["*"]` para desarrollo local.

**No exponer así en producción** sin restringir orígenes.

---

## Schema Pydantic

Definidos en `app/models/schemas.py`:

- `ScanRequest`
- `AnalyzeRequest`

---

## Consumidor principal

Frontend: `code/frontend/js/results.js` → `POST /api/scan`.

Ver [[../04-Frontend/Pantallas-UI]].
