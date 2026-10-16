"""Enumeración web para el CLI (Fase 2).

- Fuzzing de directorios con el fuzzer que haya en el sistema (ffuf, feroxbuster
  o gobuster), parseando los resultados y con fallback entre herramientas.
- Detección de rutas "interesantes" (login, admin, dashboard, upload...).
- Prueba guiada de credenciales contra un formulario de login (reutilizando las
  listas de usuarios/contraseñas que se hayan sacado por FTP, por ejemplo).

Todo pensado para labs autorizados.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

import httpx

FUZZERS = ("ffuf", "feroxbuster", "gobuster")
WORDLISTS = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)

# Palabras que hacen que una ruta descubierta merezca atención.
INTERESTING_KW = (
    "login", "signin", "sign-in", "admin", "administrator", "dashboard",
    "upload", "portal", "panel", "config", "backup", "phpmyadmin",
    "wp-login", "wp-admin", "manager", "console", "auth", "account",
)
# Marcadores típicos de login fallido / correcto.
FAIL_MARKERS = ("invalid", "incorrect", "wrong", "denied", "failed", "error",
                "try again", "no autoriz", "credenciales")
SUCCESS_MARKERS = ("logout", "log out", "dashboard", "welcome", "bienvenid",
                   "sign out", "cerrar sesión", "panel")


def find_fuzzer() -> Optional[str]:
    return next((f for f in FUZZERS if shutil.which(f)), None)


def find_wordlist() -> Optional[str]:
    return next((w for w in WORDLISTS if Path(w).is_file()), None)


# ---------------------------------------------------------------------------
# Parseo de la salida de cada fuzzer
# ---------------------------------------------------------------------------

_RE_FFUF = re.compile(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", re.M)
_RE_GOBUSTER = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?", re.M)
_RE_FEROX = re.compile(r"^\s*(\d{3})\s+\S+\s+\d+\w?\s+\S+\s+(\S+)", re.M)


def _parse_hits(tool: str, output: str, base_url: str) -> list[dict]:
    hits: list[dict] = []
    if tool == "ffuf":
        for m in _RE_FFUF.finditer(output):
            path = m.group(1)
            if path.upper() == "FUZZ":
                continue
            hits.append({"path": path, "status": int(m.group(2)), "size": int(m.group(3))})
    elif tool == "gobuster":
        for m in _RE_GOBUSTER.finditer(output):
            hits.append({"path": m.group(1).lstrip("/"), "status": int(m.group(2)),
                         "size": int(m.group(3) or 0)})
    elif tool == "feroxbuster":
        for m in _RE_FEROX.finditer(output):
            url = m.group(2)
            path = url.replace(base_url, "").lstrip("/")
            hits.append({"path": path or "/", "status": int(m.group(1)), "size": 0})
    # dedupe por path
    seen: set[str] = set()
    uniq: list[dict] = []
    for h in hits:
        if h["path"] in seen:
            continue
        seen.add(h["path"])
        uniq.append(h)
    return uniq


def _build_cmd(tool: str, base_url: str, wordlist: str, extensions: str = "php,txt,html") -> list[str]:
    """Construye el comando del fuzzer con filtros de extensión.

    Muchas máquinas esconden la ruta buena en un .php (p. ej. login.php): sin
    extensiones, ffuf/gobuster no la encuentran. Por eso añadimos -e / -x.
    """
    exts = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
    if tool == "ffuf":
        ffuf_ext = ",".join("." + e for e in exts)  # ".php,.txt,.html"
        return [tool, "-u", f"{base_url}/FUZZ", "-w", wordlist, "-e", ffuf_ext,
                "-mc", "200,204,301,302,307,401,403", "-t", "40"]
    if tool == "feroxbuster":
        return [tool, "-u", base_url, "-w", wordlist, "-x", ",".join(exts),
                "-t", "40", "-q", "--no-state"]
    return [tool, "dir", "-u", base_url, "-w", wordlist, "-x", ",".join(exts), "-t", "40", "-q"]


def run_dir_enum(base_url: str, wordlist: Optional[str] = None,
                 timeout: int = 150) -> dict[str, Any]:
    """Lanza el primer fuzzer disponible; si falla o no saca nada, prueba el siguiente."""
    wordlist = wordlist or find_wordlist()
    result: dict[str, Any] = {"tool": None, "command": None, "hits": [],
                              "raw": "", "error": None, "wordlist": wordlist}
    if not wordlist:
        result["error"] = "No encuentro un diccionario (instala seclists o usa -w)."
        return result

    tools = [f for f in FUZZERS if shutil.which(f)]
    if not tools:
        result["error"] = "No hay ffuf/gobuster/feroxbuster instalados."
        return result

    for tool in tools:
        cmd = _build_cmd(tool, base_url, wordlist)
        result["tool"] = tool
        result["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
            out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or "") + (exc.stderr or "") if isinstance(exc.stdout, str) else ""
            result["error"] = f"{tool} superó el tiempo límite ({timeout}s); uso los resultados parciales."
        except Exception as exc:
            result["error"] = f"{tool} falló: {exc}"
            continue
        result["raw"] = out
        result["hits"] = _parse_hits(tool, out, base_url)
        if result["hits"]:
            return result  # tenemos algo, no probamos más herramientas
    return result


def interesting_hits(hits: list[dict]) -> list[dict]:
    out = []
    for h in hits:
        p = h["path"].lower()
        if any(kw in p for kw in INTERESTING_KW):
            out.append(h)
    return out


def find_login_paths(hits: list[dict]) -> list[str]:
    return [h["path"] for h in hits
            if any(kw in h["path"].lower() for kw in ("login", "signin", "admin", "auth"))]


# ---------------------------------------------------------------------------
# Prueba de credenciales contra un login
# ---------------------------------------------------------------------------

_RE_INPUT = re.compile(r"<input[^>]+name=['\"]?([\w\-]+)['\"]?", re.I)


def _guess_fields(html: str) -> tuple[str, str]:
    names = [n.lower() for n in _RE_INPUT.findall(html)]
    user_field = next((n for n in names if any(k in n for k in ("user", "email", "login", "name"))), "username")
    pass_field = next((n for n in names if "pass" in n), "password")
    return user_field, pass_field


def try_login(login_url: str, users: list[str], passwords: list[str],
              max_attempts: int = 150) -> dict[str, Any]:
    """Intenta combinaciones usuario/contraseña contra un formulario de login.

    Heurística de éxito: redirección fuera del login, aparición de marcadores de
    sesión iniciada, o respuesta claramente distinta a la de fallo. Best-effort.
    """
    result: dict[str, Any] = {"success": False, "user": None, "password": None,
                              "attempts": 0, "field_user": None, "field_pass": None,
                              "evidence": None, "error": None}
    users = users or ["admin"]
    passwords = passwords or []
    if not passwords:
        result["error"] = "No hay contraseñas que probar."
        return result

    try:
        with httpx.Client(timeout=10.0, follow_redirects=False, verify=False) as client:
            base = client.get(login_url)
            u_field, p_field = _guess_fields(base.text)
            result["field_user"], result["field_pass"] = u_field, p_field
            baseline_len = len(base.text)

            attempts = 0
            for user in users:
                for pwd in passwords:
                    if attempts >= max_attempts:
                        result["error"] = f"Límite de {max_attempts} intentos alcanzado."
                        return result
                    attempts += 1
                    try:
                        resp = client.post(login_url, data={u_field: user, p_field: pwd})
                    except Exception:
                        continue
                    body = resp.text.lower()
                    redirected = resp.status_code in (301, 302, 303, 307)
                    loc = resp.headers.get("location", "").lower()
                    looks_fail = any(m in body for m in FAIL_MARKERS)
                    looks_ok = any(m in body for m in SUCCESS_MARKERS)
                    redirect_ok = redirected and "login" not in loc and loc not in ("", "/")
                    big_change = abs(len(resp.text) - baseline_len) > 120 and not looks_fail

                    if looks_ok or redirect_ok or (big_change and not looks_fail):
                        result.update({
                            "success": True, "user": user, "password": pwd,
                            "attempts": attempts,
                            "evidence": f"HTTP {resp.status_code}"
                                        + (f" → {loc}" if loc else ""),
                        })
                        return result
            result["attempts"] = attempts
    except Exception as exc:
        result["error"] = str(exc)
    return result
