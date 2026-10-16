# Instalador Linux (Fase 2)

#recontool #operaciones #fase2 #instalador

Relacionado: [[../Indice|Índice]] · [[../01-Proyecto/Fase2-CLI-e-instalador]] · [[Instalacion-y-ejecucion]] · [[Despliegue-Kali]]

---

> **Nueva agregación (Fase 2).** En la Fase 1 el arranque era `./recontool` (levantaba el servidor web con venv). Ahora hay un **instalador real** que deja ReconTool en el sistema como un programa, con el comando `recon`.

---

## Archivos

| Archivo | Función |
|---------|---------|
| `install.sh` (raíz del repo) | Instala ReconTool en el equipo |
| `uninstall.sh` (raíz del repo) | Lo elimina (respeta los informes) |

## Qué hace `install.sh`

1. Comprueba que se ejecuta como **root** (`sudo ./install.sh`).
2. Instala dependencias del sistema con `apt`:
   - **Imprescindibles:** `nmap`, `smbclient`, `python3`, `python3-venv`, `python3-pip`, `fonts-dejavu-core`.
   - **Opcionales** (no críticas): `telnet`, `ftp`, `whatweb`.
3. Copia el proyecto a **`/opt/recontool`** (`backend/` + `frontend/`), excluyendo `venv`, `__pycache__` y capturas previas.
4. Crea un **entorno virtual** en `/opt/recontool/venv` e instala `requirements.txt`.
5. Instala el lanzador **`/usr/local/bin/recon`**.

## El comando `recon`

El lanzador se relanza con `sudo` automáticamente (nmap necesita privilegios para SYN scan y `-O`). Guarda la carpeta desde la que lo llamas (`RECON_INVOKE_DIR`) para dejar ahí los informes.

```bash
recon 10.10.10.1                 # recon guiado + informe
recon 10.10.10.1 --no-exploit    # solo reconocimiento
recon 10.10.10.1 -y              # no interactivo (usa la recomendación)
recon --help
```

## Rutas

| Ruta | Contenido |
|------|-----------|
| `/opt/recontool/backend` | Código backend (copia de `code/backend`) |
| `/opt/recontool/frontend` | Frontend web (copia de `code/frontend`) |
| `/opt/recontool/venv` | Entorno virtual Python |
| `/usr/local/bin/recon` | Comando lanzador |
| `~/Desktop/` (del usuario real) | Informes entregados por defecto (`--report-dir` para cambiarlo) |

## Desinstalar

```bash
sudo ./uninstall.sh
```

Elimina `/opt/recontool` y `/usr/local/bin/recon`, limpia sesiones `/tmp/recontool-*` colgadas y **no toca** `recontool-informes/`.

---

## Enlaces

- [[../01-Proyecto/Fase2-CLI-e-instalador]]
- [[../03-Backend/Sesiones-efimeras]]
- [[Despliegue-Kali]]
