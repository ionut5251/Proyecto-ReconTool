# Mapa del repositorio

#recontool #estructura #archivos

Relacionado: [[../Indice|Índice]] · [[../06-Reglas/Que-tocar-y-que-no]]

---

## Árbol actual

```
Proyecto ReconTool/
├── .gitignore
├── bovrecon/                    ← Documentación Obsidian (esta bóveda)
│   ├── Indice.md
│   ├── 01-Proyecto/
│   ├── 02-Arquitectura/
│   ├── 03-Backend/
│   ├── 04-Frontend/
│   ├── 05-Operaciones/
│   ├── 06-Reglas/
│   └── 07-Futuro/
├── code/
│   ├── backend/
│   │   ├── .env.example         ← Plantilla configuración (commitear)
│   │   ├── .env                 ← SECRETOS — NO commitear
│   │   ├── run.py               ← Arranque uvicorn
│   │   ├── requirements.txt
│   │   ├── venv/                ← Ignorado por git
│   │   ├── data/
│   │   │   └── vulnerabilities.json
│   │   └── app/
│   │       ├── main.py          ← FastAPI + mount frontend
│   │       ├── api/routes.py
│   │       ├── core/config.py
│   │       ├── models/schemas.py
│   │       └── services/
│   │           ├── nmap_scanner.py
│   │           ├── cve_lookup.py
│   │           ├── vuln_db.py
│   │           ├── scan_pipeline.py
│   │           └── ai_advisor.py
│   └── frontend/
│       ├── index.html
│       ├── results.html
│       ├── css/styles.css
│       └── js/
│           ├── config.js
│           ├── search.js
│           └── results.js
├── docs/                        ← Vacía (reservada; doc principal = bovrecon)
└── pics/                        ← Vacía (capturas futuras para informes)
```

---

## Archivos eliminados (histórico)

| Archivo antiguo | Reemplazo |
|-----------------|-----------|
| `code/backend/main.py` | `code/backend/app/main.py` + servicios |
| `code/backend/vulnerabilities.json` | `code/backend/data/vulnerabilities.json` |

---

## Rutas URL en ejecución local

| URL | Recurso |
|-----|---------|
| `/` | `index.html` |
| `/results.html?target=IP` | Resultados |
| `/api/` | Health JSON |
| `/api/scan` | Escaneo completo |
| `/api/enrich` | Solo CVEs |
| `/api/analyze` | Solo IA |
| `/docs` | Swagger FastAPI (si no tapado por static) |

> Nota: el mount de StaticFiles en `/` puede ocultar `/docs` en algunos casos. Usar `/api/` para comprobar API viva.

---

## Copias del proyecto

| Ubicación | Uso |
|-----------|-----|
| Escritorio (`Desktop/Proyecto ReconTool`) | Desarrollo activo |
| `F:/Master/Proyecto ReconTool` | Copia original; venv antiguo puede apuntar aquí |
| Kali (futuro) | `git clone` — crear **venv nuevo** |

---

## Enlaces por carpeta de código

- Backend: [[../03-Backend/Backend-overview]]
- Frontend: [[../04-Frontend/Frontend-overview]]
- Datos CVE: [[../03-Backend/Servicio-CVE-NVD#Base local]]
