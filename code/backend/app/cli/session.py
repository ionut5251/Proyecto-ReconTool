"""Sesión efímera de ReconTool.

Modelo "borrón y cuenta nueva": cada ejecución de `recon` crea una sesión
aislada en un directorio temporal del sistema. Todo el trabajo intermedio
(capturas, descargas, logs) vive ahí dentro. Al terminar, el único artefacto
que sobrevive es el informe, que se escribe en una carpeta persistente aparte.
La sesión se destruye al salir, así que no hay base de datos de usuarios,
credenciales ni estado entre ejecuciones: volver a escanear la misma IP
arranca de cero.
"""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from typing import Any


class ReconSession:
    """Contenedor de una ejecución. Úsese como context manager."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.started_at = time.time()
        self.dir = Path(tempfile.mkdtemp(prefix="recontool-"))
        self.screenshots = self.dir / "screenshots"
        self.loot = self.dir / "loot"
        self.screenshots.mkdir(parents=True, exist_ok=True)
        self.loot.mkdir(parents=True, exist_ok=True)

        self.scan_data: dict[str, Any] = {}
        # Registro de comandos ejecutados (para la transcripción del informe).
        self.commands: list[dict[str, str]] = []

        self._redirect_screenshots()

    # -- registro de comandos -------------------------------------------------

    def log_command(self, command: str, note: str = "") -> None:
        self.commands.append(
            {
                "ts": time.strftime("%H:%M:%S"),
                "command": command,
                "note": note,
            }
        )

    # -- capturas dentro de la sesión ----------------------------------------

    def _redirect_screenshots(self) -> None:
        """Apunta la carpeta de capturas a la sesión efímera.

        Los módulos ya importados hacen `from app.core.config import
        SCREENSHOTS_DIR`, así que hay que reasignar el nombre en cada módulo,
        no solo en config.
        """
        from app.core import config as _config

        _config.SCREENSHOTS_DIR = self.screenshots
        for mod_name in ("app.services.step_capture", "app.services.report_generator"):
            try:
                import importlib

                mod = importlib.import_module(mod_name)
                if hasattr(mod, "SCREENSHOTS_DIR"):
                    mod.SCREENSHOTS_DIR = self.screenshots
            except Exception:
                pass

    # -- ciclo de vida --------------------------------------------------------

    def elapsed(self) -> float:
        return time.time() - self.started_at

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self) -> "ReconSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()
