#!/usr/bin/env bash
# Arranca ReconTool en Kali (alias corto desde code/backend).
# Preferible usar ./recontool desde la raíz del repo.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec "$ROOT/recontool"
