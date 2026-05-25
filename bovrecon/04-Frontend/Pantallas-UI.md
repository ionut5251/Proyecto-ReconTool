# Pantallas de la UI

#recontool #frontend #ui

Relacionado: [[Frontend-overview]] · [[../03-Backend/API]]

---

## Pantalla 1 — Búsqueda (`index.html`)

**Ruta:** `/`

Formulario → `/results.html?target={IP}` (`js/search.js`).

---

## Pantalla 2 — Resultados en dos fases (`results.html`)

**Ruta:** `/results.html?target={IP}`

### Fase 1 — Recon pasivo (automático al cargar)

- `POST /api/scan` (sin explotación)
- Paneles: **OSINT**, **OS**, **puertos/CVEs**, **vector detectado**
- Playbook: fuente `playbook` (sin nombres de máquina/lab en la UI)
- Botón **Proceder con ataque activo**

### Fase 2 — Ataque activo (al pulsar el botón)

- `POST /api/attack` con el JSON de la fase 1
- Pipeline, pasos de explotación (FTP o Telnet según máquina)
- **Flag capturada** + informes Word/HTML (solo si hay flag)

### Vectores por servicio (ejemplos de prueba)

| Puerto | Vector automático |
|--------|-------------------|
| 21 FTP | FTP anónimo → `flag.txt` |
| 23 Telnet | root + contraseña vacía → `flag.txt` |

En informes y resultados solo aparecen **IP** y **URL** (si hay HTTP), no nombres de máquinas de lab.

---

## Estados de carga

1. *Recon pasivo (nmap → CVE → OSINT)…*
2. Tras el botón: *Ataque activo en curso…*
