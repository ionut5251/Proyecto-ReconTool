# Qué tocar y qué NO tocar

#recontool #reglas #desarrollo

Relacionado: [[Mantenimiento-documentacion]] · [[Convenciones-de-codigo]] · [[../Indice|Índice]]

---

## ✅ TOCAR con libertad (con documentar)

| Área | Archivos | Notas |
|------|----------|-------|
| Lógica nmap | `app/services/nmap_scanner.py`, `NMAP_ARGUMENTS` en `config.py` | Actualizar [[../03-Backend/Servicio-nmap]] |
| Pipeline | `app/services/scan_pipeline.py` | Orden de fases |
| CVE local | `data/vulnerabilities.json` | Claves exactas nmap |
| NVD | `app/services/cve_lookup.py` | Rate limits |
| IA | `app/services/ai_advisor.py` | Prompts y proveedores |
| API | `app/api/routes.py`, `schemas.py` | Nuevos endpoints |
| UI | `code/frontend/**` | HTML/CSS/JS |
| Docs | `bovrecon/**` | Siempre enlazar desde [[../Indice]] |
| Deps | `requirements.txt` | Pin versions si rompe |

---

## ⚠️ TOCAR con cuidado

| Área | Motivo |
|------|--------|
| `app/main.py` | Orden router vs StaticFiles; romper `/` o `/api` |
| `run.py` | Host/puerto afecta despliegue |
| `.env.example` | Debe reflejar todas las variables de `config.py` |
| `.gitignore` | No commitear secretos por error |

---

## ❌ NO TOCAR / NO COMMITEAR

| Elemento | Motivo |
|----------|--------|
| `code/backend/.env` | Secretos (API keys) |
| `venv/` | Entorno local; regenerable |
| `__pycache__/` | Artefactos Python |
| Credenciales HTB | Nunca en repo |
| `.obsidian/workspace.json` | Opcional ignorar (estado UI personal) — si molesta en git, añadir a `.gitignore` |

---

## Añadir un componente nuevo (checklist)

1. Crear módulo en `app/services/` o ruta en `app/api/`.
2. Integrar en `scan_pipeline.py` si es parte del flujo scan.
3. Añadir nota en `bovrecon/03-Backend/` o subcarpeta adecuada.
4. Enlazar desde [[../Indice]] o [[../03-Backend/Backend-overview]].
5. Actualizar [[../02-Arquitectura/Flujo-de-datos]] si cambia el JSON.
6. Actualizar [[../01-Proyecto/Roadmap]].
7. Commit código + docs juntos.

---

## Eliminar un componente

1. Buscar referencias en código (`grep`).
2. Eliminar archivos.
3. Actualizar/eliminar notas Obsidian (no dejar enlaces rotos).
4. Mencionar en commit qué se eliminó y por qué.

---

## Para IA / colaboradores

- **Fuente de verdad del diseño:** `bovrecon/`, no suposiciones.
- **Fuente de verdad del comportamiento:** código en `code/backend/app/`.
- Ante duda: leer [[../02-Arquitectura/Mapa-del-repositorio]] primero.

---

## Enlaces

- [[Mantenimiento-documentacion]]
- [[Convenciones-de-codigo]]
