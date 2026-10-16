# Proyecto ReconTool

**Pentester automatizado en desarrollo para labs autorizados y prácticas de máster.**

ReconTool escanea un objetivo autorizado, correlaciona vulnerabilidades, te **guía por terminal** sobre qué vector probar y entrega un **informe de auditoría** con los comandos usados y la información obtenida.

> ⚠️ **Uso exclusivo en entornos autorizados**: máquinas de HackTheBox, VMs propias o redes para las que tengas permiso explícito. No lo uses contra sistemas de terceros.

---

## Fases

- **Fase 1 — web (entregada):** backend FastAPI + UI estilo Shodan en dos fases (pasiva/activa) + informe Word. Se arranca con `./recontool`.
- **Fase 2 — CLI tipo ADScan (en curso):** ReconTool se **instala en el equipo** y se usa desde terminal, con una **carpeta de trabajo por IP**. Es lo que documenta el resto de este README.

---

## Requisitos previos

- **Sistema:** Linux basado en Debian (probado en **Kali**; vale Debian/Ubuntu).
- **Permisos:** acceso **sudo/root** (nmap necesita privilegios; el instalador copia a `/opt`).
- **Base:** `git` y conexión a internet para instalar. El resto de dependencias (`nmap`, `smbclient`, Python, fuentes…) las instala `install.sh`.
- **Opcional (fuzzing web):** un fuzzer (`ffuf`, `gobuster` o `feroxbuster`) y un diccionario (p. ej. `dirb/common.txt`), ya incluidos en Kali.
- **Opcional (IA/CVE):** clave de OpenAI o un Ollama local y clave de NVD (ver `code/backend/.env.example`). Sin ellas funciona con heurística.
- **Entorno de pruebas:** VPN de HackTheBox o una VM de laboratorio autorizada.

---

## Instalación (Linux / Kali)

```bash
git clone https://github.com/ionut5251/Proyecto-ReconTool.git
cd Proyecto-ReconTool
sudo ./install.sh
```

El instalador:

- instala dependencias del sistema (`nmap`, `smbclient`, `python3-venv`, …),
- copia ReconTool a `/opt/recontool` con su propio entorno virtual,
- deja el comando **`recon`** disponible en todo el sistema.

Desinstalar: `sudo ./uninstall.sh`

---

## Uso

```bash
recon 10.10.10.1                 # reconocimiento guiado + informe
recon 10.10.10.1 --no-exploit    # solo reconocimiento
recon 10.10.10.1 -y              # no interactivo (usa la recomendación)
recon --help
```

Flujo:

1. Reconocimiento (nmap + CVE + OSINT) y resumen de puertos/servicios.
2. ReconTool **recomienda** y te **pregunta** qué vector seguir según lo que haya abierto (FTP anónimo, Telnet, SMB, fuzzing web…).
3. Ejecuta el vector elegido, te muestra lo interesante y las recomendaciones de escalada, y si encuentra la **flag** la escribe en pantalla.
4. Pulsas **finalizar** y se genera el informe.

### Encadenado FTP → web (máquinas Linux fáciles)

Si detecta FTP, ReconTool entra como anónimo, **lista todo el árbol**, descarga los ficheros interesantes (incluidas **listas de usuarios/contraseñas** tipo `allowed.userlist`) y los guarda. Si además hay un puerto web, al fuzzear encuentra rutas (login, dashboard…) y **ofrece probar esas credenciales en el login**. Si ve un **hash** recomienda `john`/`hashcat`, si ve una **clave privada** el uso por SSH. Si da con la flag, la muestra.

### Carpeta de trabajo por IP

Cada ejecución crea (o reutiliza) una carpeta con el nombre del objetivo en el directorio desde el que lanzas `recon`, y **todo se guarda ahí** (se conserva, para seguir a mano o si la sesión se corta):

```
./<ip>/
   scan.txt / scan.xml          # resultado de nmap
   loot/                        # ficheros descargados (credenciales, etc.)
   informe_pentest_<ip>_<fecha>.docx
   transcripcion_<ip>_<fecha>.md
```

No hay cuentas ni base de datos: el estado vive en esa carpeta. Cambia la ubicación base con `--report-dir <carpeta>`.

---

## Configuración (`.env.example`)

La configuración opcional (IA y consulta de CVEs) se define por variables de entorno. Copia la plantilla y rellena solo lo que uses:

```bash
cp code/backend/.env.example code/backend/.env
```

`code/backend/.env.example` incluye **todas las variables con valores ficticios** (claves de OpenAI/Ollama, NVD, nombre del auditor). No es obligatorio: sin `.env`, ReconTool usa su heurística. **Nunca** subas tu `.env` real (está en `.gitignore`).

## Datos de acceso de prueba

ReconTool **no tiene cuentas ni login**: es una herramienta local **sin autenticación** ni base de datos de usuarios, así que no hay credenciales de acceso al propio programa. Para probarlo se usa un **objetivo de laboratorio autorizado**, por ejemplo máquinas de HackTheBox fáciles:

- **Fawn** (FTP anónimo) → `recon <IP>` → vector FTP.
- **Crocodile** (FTP + web) → `recon <IP>` → FTP para sacar credenciales y luego Fuzz web.

Las únicas "credenciales" de ejemplo son los valores ficticios de `code/backend/.env.example` (API keys de IA/NVD), que no dan acceso a nada real.

## Despliegue

No se usan contenedores (Docker): ReconTool necesita acceso de red y privilegios del host para `nmap`, por lo que el **despliegue es el propio instalador** (`install.sh` → comando `recon`; `uninstall.sh` para quitarlo).

---

## Estructura del repositorio

```
Proyecto-ReconTool/
├── install.sh / uninstall.sh   # instalador Fase 2
├── recontool                   # arranque de la web (Fase 1)
├── code/                       # lo ÚNICO que instala install.sh
│   ├── backend/                # FastAPI + servicios + app/cli (CLI Fase 2)
│   └── frontend/               # UI web (Fase 1)
├── bovrecon/                   # documentación viva (Obsidian) — NO se instala
├── docs/                       # informe P1 (+ futuros writeups para la IA)
└── tools/                      # utilidades (+ futura comprobación de dependencias)
```

Solo `code/` se copia al instalar (`/opt/recontool`). `bovrecon/`, `docs/` y `tools/` son material del repo que **no hace falta para ejecutar** el programa. La **documentación completa** (arquitectura, decisiones, roadmap) vive en la bóveda Obsidian `bovrecon/` — empieza por `bovrecon/Indice.md`.

---

## Pruebas

Pruebas automatizadas de los módulos que no dependen de red (clasificación FTP,
detección de secretos, priorización de vectores, informe y sesión efímera):

```bash
cd code/backend
python3 -m venv venv && source venv/bin/activate   # si no usas el venv del instalador
pip install -r requirements.txt pytest
python -m pytest tests/ -q
```

---

## Estado

Proyecto académico en desarrollo (Máster en Ciberseguridad e IA). Ver `bovrecon/01-Proyecto/Roadmap.md`.

## Licencia

Publicado bajo licencia **MIT** (ver `LICENSE`). Uso educativo y exclusivamente en entornos autorizados.
