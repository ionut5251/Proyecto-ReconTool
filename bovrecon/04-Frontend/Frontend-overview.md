# Frontend — Visión general

#recontool #frontend

Relacionado: [[Pantallas-UI]] · [[../03-Backend/API]] · [[../02-Arquitectura/Arquitectura-general]]

---

## Tecnología

- **HTML5** estático (sin framework JS).
- **CSS** custom en `css/styles.css` (tema oscuro, acento rojo tipo Shodan).
- **JavaScript** vanilla en `js/`.

No hay build step (npm/webpack). Edición directa de archivos.

---

## Servido por FastAPI

`app/main.py` monta `code/frontend/` en `/` con `StaticFiles(html=True)`.

- `index.html` → ruta `/`
- `results.html` → `/results.html`

La API vive en `/api/*` (no colisiona con archivos estáticos nombrados).

---

## Archivos

| Archivo | Rol |
|---------|-----|
| `index.html` | Pantalla de búsqueda |
| `results.html` | Resultados + IA |
| `css/styles.css` | Estilos globales |
| `js/config.js` | `API_BASE = window.location.origin` |
| `js/search.js` | Submit → redirect con query `target` |
| `js/results.js` | Fetch scan, render tablas y panel IA |

---

## Flujo UX

1. Usuario escribe IP en home.
2. Redirect a `results.html?target=IP`.
3. `results.js` hace `POST /api/scan` automáticamente al cargar.
4. Muestra OS, puertos, CVEs y vectores IA.

Ver [[Pantallas-UI]].

---

## Modificar UI

| Cambio | Archivos |
|--------|----------|
| Colores / layout | `css/styles.css` |
| Nueva pantalla | Nuevo `.html` + enlace desde `index.html` |
| Lógica API | `js/results.js` o nuevo script |

Actualizar [[Pantallas-UI]] y [[../06-Reglas/Mantenimiento-documentacion]].

---

## Enlaces

- [[Pantallas-UI]]
- [[../07-Futuro/Auditoria-y-trazabilidad-IA]] (UI futura de pasos IA)
