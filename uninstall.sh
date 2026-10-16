#!/usr/bin/env bash
#
# ReconTool — Desinstalador
# Quita el comando `recon` y la instalación en /opt/recontool.
# No toca los informes que hayas generado (recontool-informes/).
#
set -euo pipefail

PREFIX="/opt/recontool"
BIN="/usr/local/bin/recon"

GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RST="\033[0m"
say()  { echo -e "${GREEN}[+]${RST} $*"; }
warn() { echo -e "${YELLOW}[!]${RST} $*"; }

[ "$(id -u)" -eq 0 ] || { echo -e "${RED}[x]${RST} Ejecuta como root: sudo ./uninstall.sh" >&2; exit 1; }

if [ -f "$BIN" ]; then rm -f "$BIN"; say "Eliminado $BIN"; else warn "No existe $BIN"; fi
if [ -d "$PREFIX" ]; then rm -rf "$PREFIX"; say "Eliminado $PREFIX"; else warn "No existe $PREFIX"; fi

# Sesiones efímeras que pudieran haber quedado colgadas tras un corte.
rm -rf /tmp/recontool-* 2>/dev/null || true

say "ReconTool desinstalado. Tus informes (recontool-informes/) siguen intactos."
