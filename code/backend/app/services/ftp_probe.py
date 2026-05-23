import ftplib
import io
from typing import Any, Optional

FLAG_FILENAMES = ("flag.txt", "user.txt", "root.txt")


def _append_step(steps: list[dict], action: str, detail: str, status: str = "ok") -> None:
    steps.append({"action": action, "detail": detail, "status": status})


def _retrieve_text(ftp: ftplib.FTP, filename: str) -> str:
    buffer = io.BytesIO()
    ftp.retrbinary(f"RETR {filename}", buffer.write)
    return buffer.getvalue().decode("utf-8", errors="replace").strip()


def _list_files(ftp: ftplib.FTP) -> list[str]:
    try:
        return [name for name in ftp.nlst() if name not in (".", "..")]
    except ftplib.error_perm:
        lines: list[str] = []
        ftp.retrlines("LIST", lines.append)
        return lines


def probe_ftp_anonymous(
    host: str,
    port: int = 21,
    timeout: int = 20,
) -> dict[str, Any]:
    steps: list[dict] = []
    result: dict[str, Any] = {
        "module": "ftp_anonymous",
        "host": host,
        "port": port,
        "success": False,
        "anonymous_login": False,
        "steps": steps,
        "files": [],
        "flags": [],
        "error": None,
    }

    ftp: Optional[ftplib.FTP] = None
    try:
        _append_step(steps, "connect", f"Conexión FTP a {host}:{port}")
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host, port)

        _append_step(steps, "login", "Login anonymous / anonymous@recontool.local")
        ftp.login("anonymous", "anonymous@recontool.local")
        result["anonymous_login"] = True
        _append_step(steps, "login_ok", "Acceso anónimo concedido")

        files = _list_files(ftp)
        result["files"] = files
        _append_step(steps, "list", f"Directorio remoto: {', '.join(files) or '(vacío)'}")

        targets = [f for f in files if f.lower() in FLAG_FILENAMES]
        if not targets:
            targets = [f for f in files if "flag" in f.lower() and f.lower().endswith(".txt")]

        for filename in targets:
            _append_step(steps, "download", f"Descargando {filename}")
            content = _retrieve_text(ftp, filename)
            result["flags"].append({"filename": filename, "content": content})
            _append_step(steps, "download_ok", f"{filename} obtenido ({len(content)} bytes)")
            result["success"] = True

        if result["anonymous_login"] and not result["success"]:
            _append_step(
                steps,
                "hint",
                "FTP anónimo OK pero no se encontró flag.txt — prueba: ls, get flag.txt",
                status="info",
            )

    except ftplib.error_perm as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", f"FTP rechazó la operación: {exc}", status="error")
    except (TimeoutError, OSError, ftplib.error_temp) as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", f"Error de red FTP: {exc}", status="error")
    except Exception as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", str(exc), status="error")
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                pass

    return result


def manual_ftp_playbook(host: str) -> list[str]:
    return [
        f"ftp {host}",
        "Usuario: anonymous",
        "Contraseña: (cualquier valor o Enter)",
        "ls",
        "get flag.txt",
        "exit",
        "cat flag.txt",
    ]


def run_exploitation_checks(target: str, scan_data: dict) -> dict[str, Any]:
    attempts: list[dict] = []
    ftp_ports = [
        int(row["port"])
        for row in scan_data.get("results", [])
        if str(row.get("state", "")).lower() == "open"
        and int(row.get("port", 0)) in (21, 2121)
        and str(row.get("service", "")).lower() in ("ftp", "ftps", "")
    ]

    if not ftp_ports and any(int(r.get("port", 0)) == 21 for r in scan_data.get("results", [])):
        ftp_ports = [21]

    for port in sorted(set(ftp_ports)):
        attempts.append(probe_ftp_anonymous(target, port))

    flags = [flag for attempt in attempts for flag in attempt.get("flags", [])]
    playbook_steps = manual_ftp_playbook(target) if ftp_ports else []

    return {
        "attempts": attempts,
        "flag_captured": bool(flags),
        "flags": flags,
        "playbook_steps": playbook_steps,
    }
