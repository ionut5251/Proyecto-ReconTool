"""Orquestador interactivo del CLI de ReconTool.

Flujo: recon pasivo -> mostrar hallazgos -> preguntar al usuario qué vector
seguir (con recomendación según puertos/servicios) -> ejecutar el módulo
reutilizando los servicios del backend -> informe. Todo dentro de una sesión
efímera que se borra al terminar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from app.cli import ui
from app.cli.session import ReconSession
from app.cli.transcript import build_transcript

# Etiquetas legibles para cada vector conocido.
VECTOR_LABELS = {
    "ftp_anonymous": "Conexión FTP anónima (buscar flag.txt)",
    "telnet_root_blank": "Acceso Telnet como root sin contraseña",
    "smb_anonymous": "Enumerar shares SMB anónimos",
    "http_enum": "Fuzzing / enumeración web",
}

# Nombre corto para la línea de elección del menú.
VECTOR_SHORT = {
    "ftp_anonymous": "FTP anónimo",
    "telnet_root_blank": "Telnet root",
    "smb_anonymous": "SMB anónimo",
    "http_enum": "Fuzz web",
}

FUZZERS = ("ffuf", "feroxbuster", "gobuster")
WORDLISTS = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)


# ---------------------------------------------------------------------------
# Presentación de hallazgos
# ---------------------------------------------------------------------------

def _show_findings(scan_data: dict) -> None:
    ui.section("Hallazgos del reconocimiento")

    open_rows = [r for r in scan_data.get("results", []) if str(r.get("state", "")).lower() == "open"]
    if not open_rows:
        ui.warn("No se detectaron puertos abiertos.")
    else:
        ui.ok(f"{len(open_rows)} puerto(s) abierto(s):")
        for r in open_rows:
            prod = f" {r.get('product', '')} {r.get('version', '')}".rstrip()
            ui.bullet(f"{r.get('port')}/tcp  {str(r.get('service', '?')).upper()}{prod}")

    os_info = scan_data.get("os") or []
    if os_info:
        ui.info("SO estimado: " + "; ".join(f"{o.get('name')} ({o.get('accuracy')}%)" for o in os_info[:2]))

    cve_lines = []
    for r in scan_data.get("results", []):
        for f in r.get("cve_findings") or []:
            if "error" not in f:
                cve_lines.append(f"{r.get('port')}/tcp: {f.get('cve')} ({f.get('severity')}, CVSS {f.get('cvss')})")
    if cve_lines:
        ui.info("CVEs correlacionados:")
        for line in cve_lines[:8]:
            ui.bullet(line)

    osint = scan_data.get("osint") or {}
    for w in osint.get("web") or []:
        if w.get("status"):
            title = f" — {w['title']}" if w.get("title") else ""
            ui.bullet(f"web {w.get('url')}: HTTP {w.get('status')}{title}")


# ---------------------------------------------------------------------------
# Recomendación y menú de vectores
# ---------------------------------------------------------------------------

def _recommendation_text(ids: set[str]) -> str:
    has_web = "http_enum" in ids
    if ids == {"http_enum"}:
        return (
            "Solo veo servicio web abierto. Lo natural aquí es un FUZZ de "
            "directorios y archivos para descubrir rutas ocultas."
        )
    if has_web and "ftp_anonymous" in ids:
        return (
            "Tienes web y FTP. Mi recomendación: probar primero el FTP anónimo "
            "(es rápido y en labs suele soltar flag.txt directamente); si no sale, "
            "pasamos al fuzz web."
        )
    if "telnet_root_blank" in ids:
        return "Hay Telnet: suele ser la vía más directa (root con contraseña vacía). Empezaría por ahí."
    if "smb_anonymous" in ids:
        return "Hay SMB: merece la pena enumerar shares anónimos antes que nada."
    if "ftp_anonymous" in ids:
        return "Hay FTP: el login anónimo es la prueba más rápida y rentable."
    return "Elige el vector que quieras explorar."


def _build_options(scan_data: dict) -> list[dict]:
    plan = scan_data.get("attack_plan") or {}
    primary_id = (plan.get("primary") or {}).get("id")
    options: list[dict] = []
    seen: set[str] = set()
    for v in plan.get("vectors", []):
        vid = v.get("id")
        if vid in seen:
            continue
        seen.add(vid)
        options.append(
            {
                "id": vid,
                "label": VECTOR_LABELS.get(vid, v.get("title", vid)),
                "short": VECTOR_SHORT.get(vid, VECTOR_LABELS.get(vid, vid)),
                "detail": v.get("summary", ""),
                "recommended": vid == primary_id,
            }
        )
    return options


# ---------------------------------------------------------------------------
# Ejecución de vectores
# ---------------------------------------------------------------------------

def _run_known_vector(session: ReconSession, vector_id: str) -> None:
    """FTP / Telnet / SMB: reutiliza el motor de explotación del backend."""
    from app.services.exploit_runner import run_exploitation_checks
    from app.services.playbook_advisor import build_playbook_analysis
    from app.services.step_capture import capture_all_evidence

    scan_data = session.scan_data
    target = scan_data.get("target", session.target)

    operational = {
        "vector_id": vector_id,
        "source": "user",
        "reason": "Vector elegido por el usuario en el CLI",
        "confidence": "high",
    }

    ui.info(f"Ejecutando módulo: {VECTOR_LABELS.get(vector_id, vector_id)}")
    result = run_exploitation_checks(target, scan_data, vector_id=vector_id, operational=operational)
    scan_data["exploitation"] = result
    scan_data["ai_analysis"] = build_playbook_analysis(target, scan_data, result)
    scan_data["phase"] = "active"

    for cmd in result.get("playbook_steps", []):
        session.log_command(cmd, note="playbook " + vector_id)

    for attempt in result.get("attempts", []):
        for step in attempt.get("steps", []):
            status = step.get("status", "ok")
            line = f"[{step.get('action')}] {step.get('detail')}"
            (ui.err if status == "error" else ui.bullet)(line)

    if result.get("flag_captured"):
        for f in result.get("flags", []):
            ui.flag(f"{f.get('filename')}: {f.get('content')}")
        try:
            capture_all_evidence(scan_data)
        except Exception as exc:
            ui.warn(f"No se pudieron generar capturas: {exc}")
    else:
        ui.warn(result.get("message", "Sin flag en este vector."))


def _run_ftp(session: ReconSession, port: int) -> None:
    """FTP anónimo con enumeración enriquecida (Fase 2)."""
    from app.services.ftp_probe import enumerate_ftp_anonymous, manual_ftp_playbook
    from app.services.playbook_advisor import build_playbook_analysis
    from app.services.step_capture import capture_all_evidence

    scan_data = session.scan_data
    target = scan_data.get("target", session.target)

    ui.info(f"Conectando por FTP anónimo a {target}:{port} y enumerando el árbol...")
    session.log_command(f"ftp {target} {port}    # usuario: anonymous", note="ftp")

    res = enumerate_ftp_anonymous(target, port, loot_dir=str(session.loot))

    scan_data["exploitation"] = {
        "attempts": [res],
        "flag_captured": bool(res.get("flags")),
        "flags": res.get("flags", []),
        "playbook_steps": manual_ftp_playbook(target),
        "vector_used": "ftp_anonymous",
        "message": res.get("error") or "Enumeración FTP completada",
    }
    scan_data["ai_analysis"] = build_playbook_analysis(target, scan_data, scan_data["exploitation"])
    scan_data["phase"] = "active"
    for cmd in scan_data["exploitation"]["playbook_steps"]:
        session.log_command(cmd, note="playbook ftp_anonymous")

    if not res.get("anonymous_login"):
        ui.err(f"No se pudo entrar como anónimo: {res.get('error', 'desconocido')}")
        return
    ui.ok("Login anónimo concedido.")

    listing = res.get("listing", [])
    if listing:
        ui.info(f"Contenido accesible ({len(listing)} entradas):")
        for item in listing[:40]:
            ui.bullet(item)
        if len(listing) > 40:
            ui.bullet(f"... (+{len(listing) - 40} más)")

    interesting = res.get("interesting", [])
    if interesting:
        ui.section("Ficheros interesantes (posible escalada)")
        for it in interesting:
            ui.bullet(f"{it['path']}  [{', '.join(it['tags'])}]")

    recs = res.get("recommendations", [])
    if recs:
        ui.section("Recomendaciones")
        for r in recs:
            ui.recommend(r)

    if res.get("flags"):
        ui.section("Flag")
        for f in res["flags"]:
            ui.flag(f"{f['filename']}: {f['content']}")
        try:
            capture_all_evidence(scan_data)
        except Exception as exc:
            ui.warn(f"No se pudieron generar capturas: {exc}")
    else:
        ui.warn("Sin flag directa por FTP: usa las recomendaciones para escalar (john, ssh, etc.).")


def _run_http_enum(session: ReconSession, port: int) -> None:
    """Enumeración web guiada. Si hay un fuzzer instalado, ofrece lanzarlo."""
    target = session.scan_data.get("target", session.target)
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    ui.section("Enumeración web")
    ui.info("Pasos recomendados (manual):")
    for cmd in (
        f"whatweb {base}",
        f"curl -s -I {base}",
        f"ffuf -u {base}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    ):
        ui.bullet(cmd)
        session.log_command(cmd, note="playbook http_enum")

    fuzzer = next((f for f in FUZZERS if shutil.which(f)), None)
    wordlist = next((w for w in WORDLISTS if Path(w).is_file()), None)

    if not fuzzer:
        ui.warn("No veo ffuf/gobuster/feroxbuster instalados. Instala uno para fuzzing automático.")
        return
    if not wordlist:
        ui.warn(f"{fuzzer} está instalado pero no encuentro un diccionario. Usa -w con tu wordlist.")
        return

    if not ui.ask_yes_no(f"¿Lanzo {fuzzer} contra {base} ahora?", default=False):
        return

    if fuzzer == "ffuf":
        cmd = [fuzzer, "-u", f"{base}/FUZZ", "-w", wordlist, "-mc", "200,204,301,302,307,401,403", "-t", "40"]
    elif fuzzer == "feroxbuster":
        cmd = [fuzzer, "-u", base, "-w", wordlist, "-t", "40", "-q"]
    else:  # gobuster
        cmd = [fuzzer, "dir", "-u", base, "-w", wordlist, "-t", "40", "-q"]

    session.log_command(" ".join(cmd), note="fuzzing web")
    ui.info("Lanzando (máx 180 s)... Ctrl+C para cortar.")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, errors="replace")
        out = (proc.stdout + proc.stderr).strip()
        (session.loot / "fuzz.txt").write_text(out, encoding="utf-8")
        print(out[:4000] or "(sin salida)")
        ui.ok("Salida del fuzzing guardada en la sesión.")
    except subprocess.TimeoutExpired:
        ui.warn("El fuzzing superó el tiempo límite; córtalo manualmente si hace falta.")
    except Exception as exc:
        ui.err(f"Fuzzer falló: {exc}")


# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------

def _write_reports(session: ReconSession, report_dir: Path, auditor: str, want_docx: bool) -> list[Path]:
    from app.services.report_content import safe_target

    scan_data = session.scan_data
    report_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{safe_target(scan_data.get('target', session.target))}_{datetime.now():%Y%m%d_%H%M}"
    written: list[Path] = []

    # Transcripción (siempre): comandos usados + info conseguida.
    md_path = report_dir / f"transcripcion_{tag}.md"
    md_path.write_text(build_transcript(session, auditor=auditor), encoding="utf-8")
    written.append(md_path)

    if want_docx:
        try:
            from app.services.report_generator import generate_audit_report

            docx_bytes = generate_audit_report(scan_data, auditor=auditor)
            docx_path = report_dir / f"informe_pentest_{tag}.docx"
            docx_path.write_bytes(docx_bytes)
            written.append(docx_path)
        except Exception as exc:
            ui.warn(f"No se pudo generar el .docx (queda la transcripción .md): {exc}")

    # Si corremos como sudo, devolver la propiedad de los informes al usuario real.
    _chown_to_invoker(written)
    return written


def _chown_to_invoker(paths: list[Path]) -> None:
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid:
        return
    for p in paths:
        try:
            os.chown(p, int(uid), int(gid or uid))
        except OSError:
            pass


def _invoking_user_home() -> Path:
    """Home del usuario real (no root) cuando se ejecuta con sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd as _pwd

            return Path(_pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            return Path(f"/home/{sudo_user}")
    return Path(os.path.expanduser("~"))


def _default_report_dir() -> Path:
    """Por defecto, el Escritorio del usuario que invoca (Kali)."""
    home = _invoking_user_home()
    for name in ("Desktop", "Escritorio"):
        cand = home / name
        if cand.is_dir():
            return cand
    # Si no hay Escritorio, respetar la carpeta de invocación o crear Desktop.
    base = os.environ.get("RECON_INVOKE_DIR")
    if base and Path(base).is_dir():
        return Path(base)
    return home / "Desktop"


def _port_for(scan_data: dict, vector_id: str, default: int) -> int:
    for v in (scan_data.get("attack_plan") or {}).get("vectors", []):
        if v.get("id") == vector_id and v.get("port"):
            return int(v["port"])
    return default


def _finalize_prompt(flag_found: bool, assume_yes: bool = False) -> bool:
    """El 'botón' de cierre: una sola pregunta y/n.

    - s (sí)  -> True  -> se cierra y se genera el informe.
    - n (no)  -> False -> se vuelve a mostrar el menú de vectores a seguir.

    Si se capturó flag, el valor por defecto es 'sí'; si no, 'no' (para seguir).
    """
    if assume_yes:
        return True
    return ui.ask_yes_no("¿Finalizar y generar el informe?", default=flag_found)


# ---------------------------------------------------------------------------
# Flujo principal
# ---------------------------------------------------------------------------

def run(
    target: str,
    assume_yes: bool = False,
    do_exploit: bool = True,
    report_dir: Path | None = None,
    auditor: str = "",
    want_docx: bool = True,
) -> int:
    ui.banner()
    ui.warn("Úsalo solo contra objetivos para los que tengas permiso explícito (labs, VMs propias).")

    report_dir = report_dir or _default_report_dir()

    with ReconSession(target) as session:
        ui.section(f"Objetivo: {target}")
        ui.info("Lanzando reconocimiento pasivo (nmap + CVE + OSINT)...")

        try:
            from app.core.config import NMAP_ARGUMENTS
            from app.services.scan_pipeline import run_passive_recon

            session.log_command(f"nmap {NMAP_ARGUMENTS} {target}", note="recon inicial")
            scan_data = run_passive_recon(target)
        except Exception as exc:
            ui.err(f"No se pudo completar el recon: {exc}")
            return 1

        session.scan_data = scan_data
        if scan_data.get("error"):
            ui.err(f"nmap devolvió error: {scan_data['error']}")
            return 1

        _show_findings(scan_data)

        if not do_exploit:
            ui.info("Modo solo-recon: no se ejecuta ningún vector.")
        else:
            options = _build_options(scan_data)
            if not options:
                ui.warn("No hay vector automático conocido para estos puertos.")
            else:
                ids = {o["id"] for o in options}
                ui.recommend(_recommendation_text(ids))

                tried: set[str] = set()
                while True:
                    remaining = [o for o in options if o["id"] not in tried]
                    if not remaining:
                        ui.info("No quedan vectores conocidos por probar.")
                        break
                    choice = ui.choose("¿Qué vector quieres probar?", remaining, assume_yes=assume_yes)
                    if choice is None:
                        break
                    tried.add(choice["id"])

                    if choice["id"] == "ftp_anonymous":
                        _run_ftp(session, _port_for(scan_data, "ftp_anonymous", 21))
                    elif choice["id"] == "http_enum":
                        _run_http_enum(session, _port_for(scan_data, "http_enum", 80))
                    else:
                        _run_known_vector(session, choice["id"])

                    got_flag = scan_data.get("exploitation", {}).get("flag_captured", False)
                    if _finalize_prompt(got_flag, assume_yes=assume_yes):
                        break

        # Informe (sobrevive al borrado de la sesión).
        ui.section("Informe")
        written = _write_reports(session, report_dir, auditor, want_docx)
        for p in written:
            ui.ok(f"Guardado: {p}")

        ui.section("Cierre de sesión")
        ui.info("Borrón y cuenta nueva: elimino todos los datos temporales de esta sesión.")

    ui.ok("Sesión cerrada. Volver a escanear la misma IP empezará de cero.")
    return 0
