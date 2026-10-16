"""Punto de entrada del comando `recon`.

Uso tras instalar:
    recon 10.10.10.1
    recon 10.10.10.1 --no-exploit
    recon 10.10.10.1 -y            (no interactivo: elige la recomendación)
    recon 10.10.10.1 --report-dir ~/informes
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from app.cli import ui

__version__ = "0.3.0"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon",
        description="ReconTool — reconocimiento activo guiado para labs autorizados.",
    )
    p.add_argument("target", nargs="?", help="IP o hostname del objetivo (lab autorizado)")
    p.add_argument("-y", "--yes", action="store_true", help="No interactivo: usa la recomendación automática")
    p.add_argument("--no-exploit", action="store_true", help="Solo reconocimiento, sin ejecutar vectores")
    p.add_argument("--report-dir", type=Path, default=None,
                   help="Carpeta base donde crear la carpeta por IP (por defecto, desde donde lanzas recon)")
    p.add_argument("--auditor", default="", help="Nombre del auditor para el informe")
    p.add_argument("--no-docx", action="store_true", help="No generar .docx (solo transcripción .md)")
    p.add_argument("--version", action="version", version=f"ReconTool CLI {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.target:
        ui.banner()
        ui.err("Falta el objetivo. Ejemplo: recon 10.10.10.1")
        ui.info("Ayuda: recon --help")
        return 2

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        ui.warn(
            "No estás como root: nmap no podrá hacer SYN scan ni detección de SO. "
            "El comando instalado `recon` ya se relanza con sudo automáticamente."
        )

    # Import diferido: así `recon --help` y `--version` no requieren nmap.
    from app.cli import runner

    try:
        return runner.run(
            target=args.target,
            assume_yes=args.yes,
            do_exploit=not args.no_exploit,
            report_dir=args.report_dir,
            auditor=args.auditor,
            want_docx=not args.no_docx,
        )
    except KeyboardInterrupt:
        print()
        ui.warn("Interrumpido por el usuario. Limpiando sesión...")
        return 130


if __name__ == "__main__":
    sys.exit(main())
