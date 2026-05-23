#!/usr/bin/env bash
# Arranca ReconTool en Kali usando el venv (nmap necesita root para -sS/-O).
set -e
cd "$(dirname "$0")"

if [[ ! -x venv/bin/python ]]; then
  echo "ERROR: No existe venv/bin/python"
  echo "Ejecuta primero:"
  echo "  python3 -m venv venv"
  echo "  ./venv/bin/pip install -r requirements.txt"
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "ERROR: nmap no está instalado (binario del sistema)."
  echo "  sudo apt update && sudo apt install -y nmap"
  exit 1
fi

echo "Python del venv: $(./venv/bin/python -c 'import sys; print(sys.executable)')"
echo "Arrancando con sudo (nmap -sS requiere privilegios)..."
echo ""
echo "  NO uses: sudo python run.py   (eso usa Python del sistema sin dependencias)"
echo "  USA:     sudo ./venv/bin/python run.py"
echo ""

exec sudo ./venv/bin/python run.py
