"""Utilidades de interfaz para el CLI de ReconTool (colores ANSI y prompts).

Sin dependencias externas: solo stdlib. Si la salida no es una terminal
(por ejemplo redirigida a un archivo), los colores se desactivan solos.
"""

from __future__ import annotations

import sys

_USE_COLOR = sys.stdout.isatty()


class C:
    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""
    RED = "\033[31m" if _USE_COLOR else ""
    GREEN = "\033[32m" if _USE_COLOR else ""
    YELLOW = "\033[33m" if _USE_COLOR else ""
    BLUE = "\033[34m" if _USE_COLOR else ""
    CYAN = "\033[36m" if _USE_COLOR else ""
    GREY = "\033[90m" if _USE_COLOR else ""


def banner() -> None:
    print(
        f"""{C.GREEN}{C.BOLD}
  ____                    _____           _
 |  _ \\ ___  ___ ___  _ _|_   _|__   ___ | |
 | |_) / _ \\/ __/ _ \\| '_ \\| |/ _ \\ / _ \\| |
 |  _ <  __/ (_| (_) | | | | | (_) | (_) | |
 |_| \\_\\___|\\___\\___/|_| |_|_|\\___/ \\___/|_|
{C.RESET}{C.GREY}  Reconocimiento activo guiado · solo objetivos autorizados (labs){C.RESET}
"""
    )


def section(title: str) -> None:
    print(f"\n{C.BOLD}{C.BLUE}== {title} =={C.RESET}")


def info(msg: str) -> None:
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.RED}[x]{C.RESET} {msg}")


def flag(msg: str) -> None:
    print(f"{C.GREEN}{C.BOLD}[FLAG]{C.RESET} {C.GREEN}{msg}{C.RESET}")


def recommend(msg: str) -> None:
    print(f"{C.YELLOW}{C.BOLD}[Recomendación]{C.RESET} {msg}")


def bullet(msg: str) -> None:
    print(f"   {C.GREY}-{C.RESET} {msg}")


def ask_yes_no(question: str, default: bool = True, assume_yes: bool = False) -> bool:
    """Pregunta sí/no. assume_yes salta la interacción (modo no interactivo)."""
    suffix = "[S/n]" if default else "[s/N]"
    if assume_yes:
        print(f"{C.YELLOW}[?]{C.RESET} {question} {suffix} {C.DIM}(auto: sí){C.RESET}")
        return True
    while True:
        try:
            raw = input(f"{C.YELLOW}[?]{C.RESET} {question} {suffix} ").strip().lower()
        except EOFError:
            return default
        if not raw:
            return default
        if raw in ("s", "si", "sí", "y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        warn("Responde 's' o 'n'.")


def choose(question: str, options: list[dict], assume_yes: bool = False) -> dict | None:
    """Menú numerado. Cada opción es {id, label, detail, recommended}.

    Devuelve la opción elegida, o None si el usuario decide saltar.
    En modo assume_yes elige automáticamente la recomendada (o la primera).
    """
    default_idx = next((i for i, o in enumerate(options) if o.get("recommended")), 0)

    print(f"\n{C.YELLOW}[?]{C.RESET} {question}")
    for i, opt in enumerate(options):
        tag = f" {C.GREEN}(recomendado){C.RESET}" if opt.get("recommended") else ""
        print(f"   {C.BOLD}{i + 1}{C.RESET}) {opt['label']}{tag}")
        if opt.get("detail"):
            print(f"      {C.GREY}{opt['detail']}{C.RESET}")
    print(f"   {C.BOLD}0{C.RESET}) Saltar / no ejecutar nada")

    if assume_yes:
        chosen = options[default_idx]
        print(f"   {C.DIM}(auto: {chosen['label']}){C.RESET}")
        return chosen

    # Línea de elección con el nombre de cada opción, no solo el número.
    def _name(opt: dict) -> str:
        return opt.get("short") or opt["label"]

    parts = "  ·  ".join(f"[{i + 1}] {_name(opt)}" for i, opt in enumerate(options))
    default_name = _name(options[default_idx])

    while True:
        try:
            raw = input(
                f"   {parts}  ·  [0] saltar   {C.DIM}(Enter = {default_name}){C.RESET}: "
            ).strip()
        except EOFError:
            return options[default_idx]
        if not raw:
            return options[default_idx]
        if raw == "0":
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        warn(f"Opción no válida. Escribe un número del 1 al {len(options)}, o 0 para saltar.")
