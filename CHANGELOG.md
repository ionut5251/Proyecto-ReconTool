# Changelog

Formato basado en *Keep a Changelog*. El detalle y las decisiones de diseño
están en la bóveda: `bovrecon/01-Proyecto/Changelog-P1-a-P3.md`.

## [0.3.0] — 2026-10-16

### Cambiado
- **Carpeta de trabajo por IP** persistente (`./<ip>/`) en lugar de sesión temporal
  que se borraba: ahí van `scan.txt`/`scan.xml` (nmap), `loot/`, e informes.
- Menú de vectores con nombres (`[1] FTP anónimo · [2] Fuzz web · …`).

### Añadido
- FTP reconoce y descarga **listas de usuarios/contraseñas** (allowed.userlist, *.passwd…)
  y las deja listas para reutilizar.
- Enumeración web (`http_enum`): fuzzing con **ffuf/gobuster/feroxbuster** (con fallback),
  parseo de rutas, detección de rutas interesantes (login/dashboard…) y **prueba de las
  credenciales del FTP contra el login** (encadenado).
- Instalador tolerante a errores de `apt` de terceros.

## [v1.0-practica3] — 2026-10-16

### Añadido
- Instalador Linux (`install.sh` / `uninstall.sh`) y comando `recon`.
- CLI guiado interactivo (`code/backend/app/cli/`) con sesiones efímeras
  ("borrón y cuenta nueva").
- Enumeración FTP enriquecida: listado completo, ficheros interesantes,
  detección de hashes/claves/credenciales y recomendaciones (john, ssh…).
- Botón de finalizar e informe de auditoría (`.docx` + transcripción `.md`),
  por defecto en el Escritorio.
- Pruebas automatizadas (`code/backend/tests/`, pytest).
- README reescrito y `.gitignore` ampliado.

### Cambiado
- La interfaz principal pasa de la web a un **CLI** tipo ADScan; la web de la
  Práctica 1 se mantiene disponible sobre el mismo backend.

### Base (Práctica 1)
- Aplicación web FastAPI: nmap → CVE → OSINT → IA → explotación
  (FTP/Telnet/SMB) → informe Word/HTML.
