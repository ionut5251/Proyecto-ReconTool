#!/usr/bin/env bash
#
# ReconTool — Instalador para Linux (Kali / Debian / Ubuntu)
# -----------------------------------------------------------
# Deja ReconTool instalado en el equipo como un programa más:
#   - Instala dependencias del sistema (nmap, smbclient, ...).
#   - Copia el proyecto a /opt/recontool.
#   - Crea un entorno virtual de Python con las dependencias.
#   - Instala el comando `recon` en /usr/local/bin.
#
# Modelo de sesión efímera: cada vez que ejecutas `recon <ip>` se crea una
# sesión aislada que se borra al terminar. No hay cuentas ni base de datos:
# el único resultado que se conserva es el informe.
#
# Uso:   sudo ./install.sh
#
set -eo pipefail

PREFIX="/opt/recontool"
BIN="/usr/local/bin/recon"
SRC="$(cd "$(dirname "$0")" && pwd)"

GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; BOLD="\033[1m"; RST="\033[0m"
say()  { echo -e "${GREEN}[+]${RST} $*"; }
warn() { echo -e "${YELLOW}[!]${RST} $*"; }
die()  { echo -e "${RED}[x]${RST} $*" >&2; exit 1; }

# --- 0. Comprobaciones previas ---------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Ejecuta el instalador como root:  sudo ./install.sh"
[ -d "$SRC/code/backend" ] || die "No encuentro code/backend junto a este script."

echo -e "${BOLD}== Instalador de ReconTool ==${RST}"
say "Origen:  $SRC"
say "Destino: $PREFIX"
echo ""

# --- 1. Dependencias del sistema -------------------------------------------
# Importante: 'apt-get update' puede fallar por repositorios de TERCEROS ya
# configurados en el sistema (p. ej. MongoDB con clave SHA1 que Kali rechaza).
# Eso es ajeno a ReconTool, así que NO abortamos la instalación por ello:
# seguimos con las listas de paquetes que sí se hayan podido actualizar.
if command -v apt-get >/dev/null 2>&1; then
    say "[1/4] Instalando dependencias del sistema (apt)..."
    export DEBIAN_FRONTEND=noninteractive

    if ! apt-get update -y; then
        warn "apt-get update devolvió errores (normalmente por repos de terceros ajenos a ReconTool). Continúo con lo disponible."
    fi

    # Imprescindibles. Si apt falla aquí, avisamos y verificamos al final.
    if ! apt-get install -y nmap smbclient python3 python3-venv python3-pip fonts-dejavu-core; then
        warn "Algún paquete del sistema no se pudo instalar vía apt; lo verifico al terminar."
    fi

    # Útiles para los playbooks manuales (no críticos si fallan).
    apt-get install -y telnet ftp whatweb 2>/dev/null \
        || warn "Paquetes opcionales (telnet/ftp/whatweb) no instalados; no es crítico."
else
    warn "No detecto apt-get. Instala manualmente: nmap, smbclient, python3-venv, python3-pip, fuentes DejaVu."
fi

# --- 2. Copia del proyecto a /opt ------------------------------------------
say "[2/4] Copiando ReconTool a $PREFIX ..."
mkdir -p "$PREFIX"
copy_tree() {  # origen destino
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude 'venv' --exclude '__pycache__' --exclude '*.pyc' \
            --exclude 'data/screenshots/*' \
            "$1/" "$2/"
    else
        rm -rf "$2"; mkdir -p "$2"
        cp -r "$1/." "$2/"
        find "$2" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
        rm -rf "$2/venv" 2>/dev/null || true
    fi
}
copy_tree "$SRC/code/backend" "$PREFIX/backend"
copy_tree "$SRC/code/frontend" "$PREFIX/frontend"

# --- 3. Entorno virtual + dependencias Python ------------------------------
say "[3/4] Creando entorno virtual e instalando dependencias Python..."
command -v python3 >/dev/null 2>&1 || die "python3 no está instalado. Instálalo:  sudo apt-get install -y python3 python3-venv  y reintenta."
if ! python3 -m venv "$PREFIX/venv"; then
    die "No se pudo crear el entorno virtual. Instala python3-venv:  sudo apt-get install -y python3-venv  y reintenta."
fi
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip || warn "No se pudo actualizar pip; continúo."
"$PREFIX/venv/bin/pip" install --quiet -r "$PREFIX/backend/requirements.txt" \
    || die "Fallo instalando las dependencias de Python (requirements.txt). Revisa tu conexión y reintenta."

# --- 4. Comando `recon` en el PATH -----------------------------------------
say "[4/4] Instalando el comando 'recon' en $BIN ..."
cat > "$BIN" <<'LAUNCHER'
#!/usr/bin/env bash
# Lanzador de ReconTool. Se relanza con sudo porque nmap necesita privilegios
# para el SYN scan y la detección de SO.
set -e
RECON_HOME="/opt/recontool"
# Carpeta desde la que el usuario invoca: ahí se dejan los informes.
export RECON_INVOKE_DIR="${RECON_INVOKE_DIR:-$PWD}"
cd "$RECON_HOME/backend"
PY="$RECON_HOME/venv/bin/python"
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -E "$PY" -m app.cli.main "$@"
fi
exec "$PY" -m app.cli.main "$@"
LAUNCHER
chmod +x "$BIN"

# --- Verificación final ----------------------------------------------------
echo ""
MISSING=0
command -v nmap >/dev/null 2>&1 || { warn "nmap NO está instalado: el escaneo no funcionará. Instálalo con: sudo apt-get install -y nmap"; MISSING=1; }
command -v smbclient >/dev/null 2>&1 || { warn "smbclient NO está instalado: el módulo SMB no funcionará. Instálalo con: sudo apt-get install -y smbclient"; MISSING=1; }

echo ""
echo -e "${BOLD}${GREEN}ReconTool instalado correctamente.${RST}"
[ "$MISSING" -eq 1 ] && warn "Faltan herramientas del sistema (ver arriba): instálalas y ReconTool funcionará al 100%."
echo ""
echo "  Uso básico:"
echo -e "     ${BOLD}recon 10.10.10.1${RST}            # recon guiado + informe"
echo -e "     ${BOLD}recon 10.10.10.1 --no-exploit${RST}  # solo reconocimiento"
echo -e "     ${BOLD}recon --help${RST}"
echo ""
echo "  Los informes se guardan por defecto en tu Escritorio (~/Desktop)."
echo "  Desinstalar:  sudo ./uninstall.sh"
echo ""
warn "Recuerda: úsalo solo contra objetivos autorizados (HTB, VMs propias, red propia)."
