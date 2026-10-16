"""Sesión de trabajo de ReconTool (carpeta por IP, persistente).

Cada ejecución de `recon <ip>` crea (o reutiliza) una carpeta con el nombre del
objetivo dentro del directorio desde el que se lanza:

    ./<ip>/
        scan.txt / scan.xml      <- resultado de nmap (para 'cat' o uso manual)
        loot/                    <- ficheros descargados (credenciales, etc.)
        screenshots/             <- evidencias
        informe_pentest_*.docx
        transcripcion_*.md

La carpeta NO se borra al terminar: así, si la sesión se corta o quieres seguir
a mano más tarde, tienes el scan y el botín a mano. No hay cuentas ni base de
datos de usuarios; el estado vive en esa carpeta y nada más.
"""

from __future__ import annotations

import importlib
import re
import time
from pathlib import Path
from typing import Any


def safe_name(target: str) -> str:
    return re.sub(r"[^\w.\-]", "_", str(target))


class ReconSession:
    """Carpeta de trabajo por objetivo. Úsese como context manager."""

    def __init__(self, target: str, base_dir: str | Path) -> None:
        self.target = target
        self.started_at = time.time()
        self.base_dir = Path(base_dir)
        self.dir = self.base_dir / safe_name(target)
        self.loot = self.dir / "loot"
        self.screenshots = self.dir / "screenshots"
        for d in (self.dir, self.loot, self.screenshots):
            d.mkdir(parents=True, exist_ok=True)

        self.scan_data: dict[str, Any] = {}
        self.commands: list[dict[str, str]] = []
        # Credenciales descubiertas durante la sesión, para reutilizar entre módulos.
        self.creds: dict[str, list[str]] = {"users": [], "passwords": [], "files": []}

        self._redirect_screenshots()

    # -- registro de comandos -------------------------------------------------

    def log_command(self, command: str, note: str = "") -> None:
        self.commands.append(
            {"ts": time.strftime("%H:%M:%S"), "command": command, "note": note}
        )

    # -- credenciales ---------------------------------------------------------

    def add_users(self, users: list[str]) -> None:
        for u in users:
            if u and u not in self.creds["users"]:
                self.creds["users"].append(u)

    def add_passwords(self, passwords: list[str]) -> None:
        for p in passwords:
            if p and p not in self.creds["passwords"]:
                self.creds["passwords"].append(p)

    def has_creds(self) -> bool:
        return bool(self.creds["users"] or self.creds["passwords"])

    # -- capturas dentro de la carpeta de la sesión ---------------------------

    def _redirect_screenshots(self) -> None:
        from app.core import config as _config

        _config.SCREENSHOTS_DIR = self.screenshots
        for mod_name in ("app.services.step_capture", "app.services.report_generator"):
            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, "SCREENSHOTS_DIR"):
                    mod.SCREENSHOTS_DIR = self.screenshots
            except Exception:
                pass

    # -- ciclo de vida --------------------------------------------------------

    def elapsed(self) -> float:
        return time.time() - self.started_at

    def __enter__(self) -> "ReconSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Persistente: NO se borra la carpeta.
        return None
