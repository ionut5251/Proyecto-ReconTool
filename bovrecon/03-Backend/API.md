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

**Fase 1 — recon pasivo** (por defecto): nmap + CVE + OSINT + plan de ataque. **No explota.**

**Body (JSON):**

| Campo | Tipo | Default | Descripción |
|-------|------|---------|-------------|
| `target` | string | *requerido* | IP o hostname |
| `enrich_cve` | bool | `true` | Consultar NVD + base local |
| `osint` | bool | `true` | Reverse DNS, probe HTTP, notas |
| `full_pipeline` | bool | `false` | Si `true`, ejecuta también ataque (legacy) |

**Ejemplo curl:**

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"target\": \"10.129.8.152\", \"enrich_cve\": true, \"osint\": true}"
```

Respuesta incluye: `phase: "passive"`, `attack_plan`, `osint`, `exploitation.pending: true`.

---

### `POST /api/attack`

**Fase 2 — ataque activo** según `attack_plan` (FTP Fawn, Telnet Meow, etc.).

**Body:**

```json
{
  "scan_data": { "... resultado de /api/scan ..." },
  "ai_analyze": true
}
```

Devuelve `phase: "active"`, `exploitation`, capturas si hay flag.

---

### Pipeline legacy

`POST /api/scan` con `"full_pipeline": true` ejecuta pasivo + activo en una sola petición (comportamiento anterior).

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

Genera informe de auditoría. **Solo si hay flag capturada.**

**Body:**

```json
{
  "scan_data": { "...": "resultado completo de /api/scan" },
  "format": "docx",
  "auditor": "Tu Nombre (opcional)"
}
```

| `format` | Salida |
|----------|--------|
| `docx` | Word (default) |
| `html` | HTML para Kali/Firefox — imágenes embebidas |

Ver [[Servicio-informe-Word]] y [[Servicio-capturas-automaticas]].

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
