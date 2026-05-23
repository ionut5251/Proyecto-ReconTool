# Pantallas de la UI

#recontool #frontend #ui

Relacionado: [[Frontend-overview]] · [[../03-Backend/API]]

---

## Pantalla 1 — Búsqueda (`index.html`)

**Ruta:** `/`

Elementos:

- Logo **ReconTool** (enlace a home).
- Tagline académico.
- Formulario `#search-form` con input `#target-input`.
- Botón **Escanear**.
- Aviso legal: solo objetivos autorizados.

**Comportamiento** (`js/search.js`):

```javascript
// Al submit → /results.html?target={IP}
```

---

## Pantalla 2 — Resultados (`results.html`)

**Ruta:** `/results.html?target={IP}`

### Cabecera

- Logo + mini-búsqueda (`#mini-search`) para cambiar IP sin volver a home.

### Banner objetivo

- `#target-title` — IP mostrada.
- `#scan-status` — estados: preparando → escaneando → completado / error.

### Paneles

| ID | Contenido |
|----|-----------|
| `#error-panel` | Errores de API/nmap |
| `#os-panel` | Lista OS detectado (nmap `osmatch`) |
| `#ports-panel` | Tabla puertos y servicios |
| `#empty-panel` | Sin puertos abiertos (`--open`) |
| `#ai-panel` | Vectores sugeridos por IA |
| `#ai-disabled-panel` | Mensaje si IA no configurada |

### Tabla de puertos

Columnas: Puerto, Estado, Servicio, Producto/versión, Info extra, **CVEs detectados**.

Render de CVEs (`results.js`):

- Usa `cve_findings[]` si existe.
- Fallback a `vulnerability` única.
- Badges por severidad (`critical`, `high`).

### Panel IA

Muestra:

- `analysis.summary`
- Tarjetas por cada `analysis.vectors[]` (título, prioridad, rationale, checks, puertos).
- Lista `analysis.next_steps`
- Meta: proveedor y modelo.

Si `ai_analysis.enabled === false` → panel gris con mensaje de `.env`.

---

## Estados de carga

Un solo request largo a `/api/scan`. El usuario ve:

> *Escaneando con nmap, consultando NVD y generando vectores IA (puede tardar varios minutos)…*

Mejora futura: progreso por fases (nmap / CVE / IA).

---

## Accesibilidad y responsive

- CSS con `@media (max-width: 640px)` para cabecera en móvil.
- Sin dependencias externas (funciona offline excepto API).

---

## Enlaces

- [[Frontend-overview]]
- [[../02-Arquitectura/Flujo-de-datos]]
