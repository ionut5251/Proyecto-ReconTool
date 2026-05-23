# Convenciones de código

#recontool #reglas #codigo

Relacionado: [[Que-tocar-y-que-no]] · [[../03-Backend/Backend-overview]]

---

## Python (backend)

| Regla | Detalle |
|-------|---------|
| Idioma comentarios | Español o inglés; coherente por archivo |
| Tipado | Preferir type hints en funciones públicas |
| Estructura | Un servicio = un archivo en `app/services/` |
| Config | Solo en `app/core/config.py` + `.env`, no hardcodear keys |
| Errores API | Por ahora `{ "error": str }` en body; documentar si cambia |
| Imports | Absolutos desde `app.` (`from app.services...`) |

---

## JavaScript (frontend)

| Regla | Detalle |
|-------|---------|
| Sin frameworks | Vanilla JS |
| API base | `config.js` → `window.location.origin` |
| XSS | Usar `escapeHtml()` al insertar datos del scan en HTML |
| IDs DOM | Mantener sincronía con `results.html` |

---

## JSON / datos

- Respuestas API en **snake_case** (`cve_findings`, `ai_analysis`).
- No romper campos existentes sin actualizar frontend y [[../02-Arquitectura/Flujo-de-datos]].

---

## Nombres de archivos

- Python: `snake_case.py`
- Notas Obsidian: `Titulo-con-guiones.md` (legible en grafo)
- CSS/JS: `snake_case` o `kebab-case` según carpeta existente

---

## Ethical use

Cualquier automatización de ataque debe ir detrás de:

- Confirmación de scope autorizado.
- Logs y auditoría (futuro).

Ver [[../01-Proyecto/Vision-y-objetivos]].

---

## Enlaces

- [[Mantenimiento-documentacion]]
- [[../03-Backend/Pipeline-de-escaneo]]
