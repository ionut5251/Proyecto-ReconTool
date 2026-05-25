"""Logo y recursos de marca para informes."""

from __future__ import annotations

import base64

from app.core.config import LOGO_PATH


def logo_exists() -> bool:
    return LOGO_PATH.is_file()


def logo_base64() -> str | None:
    if not logo_exists():
        return None
    return base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")


def logo_path_str() -> str | None:
    if not logo_exists():
        return None
    return str(LOGO_PATH)
