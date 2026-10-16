"""Orquestador interactivo del CLI de ReconTool (Fase 2).

Flujo: crea una carpeta de trabajo por IP, lanza el recon (nmap+CVE+OSINT) y
guarda el scan, muestra hallazgos y deja que el usuario encadene vectores:
FTP (saca y guarda credenciales) -> web (fuzzing + login probando esas
credenciales) -> informe. Todo se queda en ./<ip>/.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from app.cli import ui
from app.cli.session import ReconSession
from app.cli.transcript import build_transcript

VECTOR_LABELS = {
    "ftp_anonymous": "Conexión FTP anónima (enumerar y sacar credenciales)",
    "telnet_root_blank": "Acceso Telnet como root sin contraseña",
    "smb_anonymous": "Enumerar shares SMB anónimos",
    "http_enum": "Fuzzing / enumeración web (+ login)",
}

VECTOR_SHORT = {
    "ftp_anonymous": "FTP anónimo",
    "telnet_root_blank": "Telnet root",
    "smb_anonymous": "SMB anónimo",
    "http_enum": "Fuzz web",
}


# ---------------------------------------------------------------------------
# Carpeta de trabajo / rutas
# ---------------------------------------------------------------------------

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


def _invoking_base_dir() -> Path:
    """Base donde crear la carpeta por IP: el Escritorio del usuario (fácil de encontrar)."""
    home = _invoking_user_home()
    for name in ("Desktop", "Escritorio"):
        d = home / name
        if d.is_dir():
            return d
    d = home / "Desktop"
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except OSError:
        return Path(os.environ.get("RECON_INVOKE_DIR") or os.getcwd())


def _chown_tree_to_invoker(root: Path) -> None:
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid:
        return
    try:
        for p in [root, *root.rglob("*")]:
            os.chown(p, int(uid), int(gid or uid))
    except OSError:
        pass


def _port_for(scan_data: dict, vector_id: str, default: int) -> int:
    for v in (scan_data.get("attack_plan") or {}).get("vectors", []):
        if v.get("id") == vector_id and v.get("port"):
            return int(v["port"])
    return default


# ---------------------------------------------------------------------------
# nmap -> fichero scan
# ---------------------------------------------------------------------------

def _write_scan_files(session: ReconSession) -> None:
    from app.core.config import NMAP_ARGUMENTS
    from app.services.report_content import ports_summary

    scan_data = session.scan_data
    lines = [
        f"# ReconTool - nmap scan de {scan_data.get('target', session.target)}",
        f"# Comando: {scan_data.get('_nmap_command') or 'nmap ' + NMAP_ARGUMENTS}",
        f"# Fecha: {datetime.now():%Y-%m-%d %H:%M}",
        "",
        "Puertos abiertos:",
    ]
    for r in scan_data.get("results", []):
        if str(r.get("state", "")).lower() == "open":
            prod = f" {r.get('product', '')} {r.get('version', '')}".rstrip()
            lines.append(f"  {r.get('port')}/tcp  {r.get('service', '?')}{prod}")
    os_info = scan_data.get("os") or []
    if os_info:
        lines.append("")
        lines.append("SO estimado: " + "; ".join(f"{o.get('name')} ({o.get('accuracy')}%)" for o in os_info[:3]))
    lines.append("")
    lines.append(f"Resumen: {ports_summary(scan_data)}")
    (session.dir / "scan.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    xml = scan_data.get("_nmap_xml")
    if xml:
        (session.dir / "scan.xml").write_text(xml, encoding="utf-8")
    session.log_command(scan_data.get("_nmap_command") or f"nmap {NMAP_ARGUMENTS} {session.target}",
                        note="recon inicial (guardado en scan.txt/scan.xml)")


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


def _recommendation_text(ids: set[str]) -> str:
    has_web = "http_enum" in ids
    if has_web and "ftp_anonymous" in ids:
        return (
            "Tienes FTP y web. Plan sugerido: (1) FTP anónimo para sacar ficheros/"
            "credenciales, (2) fuzz del puerto 80 para encontrar login/paneles, "
            "(3) probar esas credenciales en el login. Empieza por el FTP."
        )
    if ids == {"http_enum"}:
        return "Solo veo web: lo natural es un FUZZ de directorios para descubrir rutas (login, paneles...)."
    if "telnet_root_blank" in ids:
        return "Hay Telnet: suele ser la vía más directa (root con contraseña vacía)."
    if "smb_anonymous" in ids:
        return "Hay SMB: enumera shares anónimos antes que nada."
    if "ftp_anonymous" in ids:
        return "Hay FTP: empieza por el login anónimo y mira qué hay."
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
# Vectores
# ---------------------------------------------------------------------------

def _run_ftp(session: ReconSession, port: int) -> None:
    from app.services.ftp_probe import (
        enumerate_ftp_anonymous, manual_ftp_playbook, parse_credential_lists, try_ftp_login,
    )
    from app.services.playbook_advisor import build_playbook_analysis
    from app.services.step_capture import capture_all_evidence

    scan_data = session.scan_data
    target = scan_data.get("target", session.target)

    ui.info(f"Conectando por FTP anónimo a {target}:{port} y enumerando...")
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

    interesting = res.get("interesting", [])
    if interesting:
        ui.section("Ficheros interesantes (descargados a la carpeta loot/)")
        for it in interesting:
            ui.bullet(f"{it['path']}  [{', '.join(it['tags'])}]")

    # Atar cabos: convertir userlist/passwd descargados en listas reutilizables.
    users, passwords = parse_credential_lists(str(session.loot))
    if users or passwords:
        session.add_users(users)
        session.add_passwords(passwords)
        session.creds["files"] = [i["path"] for i in interesting]
        ui.ok(f"Credenciales candidatas guardadas en loot/: {len(users)} usuario(s), {len(passwords)} contraseña(s).")
        ui.info("Voy a usar esas credenciales contra el propio servicio FTP...")
        session.log_command(
            f"# probar {len(users)}x{len(passwords)} credenciales (FTP autenticado) en {target}",
            note="ftp login")
        fl = try_ftp_login(target, users, passwords, port=port)
        valid = fl.get("valid") or []
        if valid:
            ui.flag(f"{len(valid)} combinación(es) válida(s) en el FTP:")
            for c in valid:
                ui.bullet(f"usuario: {c['user']}   contraseña: {c['password']}")
            if fl.get("files"):
                ui.info("Contenido de esa cuenta FTP:")
                for fn in fl["files"][:40]:
                    ui.bullet(fn)
        else:
            ui.warn("Ninguna combinación encontrada para el FTP.")

    # Recomendaciones útiles (hash/clave); omito la genérica "revísalos a mano".
    for rec in res.get("recommendations", []):
        if "Revísalos a mano" not in rec:
            ui.recommend(rec)

    if res.get("flags"):
        ui.section("Flag")
        for f in res["flags"]:
            ui.flag(f"{f['filename']}: {f['content']}")
        try:
            capture_all_evidence(scan_data)
        except Exception as exc:
            ui.warn(f"No se pudieron generar capturas: {exc}")
    elif not (users or passwords):
        ui.warn("Sin flag ni credenciales directas por FTP.")


def _open_in_browser(url: str) -> None:
    import shutil
    import subprocess

    sudo_user = os.environ.get("SUDO_USER")
    opener = shutil.which("xdg-open") or shutil.which("firefox")
    if not opener:
        ui.info(f"Ábrelo tú en el navegador: {url}")
        return
    try:
        cmd = ["sudo", "-u", sudo_user, opener, url] if sudo_user else [opener, url]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ui.ok(f"Abriendo {url} en el navegador...")
    except Exception as exc:
        ui.info(f"No pude abrir el navegador ({exc}). Ábrelo tú: {url}")


def _manual_login_fallback(session: ReconSession, login_url: str, assume_yes: bool, web_record: dict) -> None:
    """Cuando no se puede confirmar el login desde el CLI: lo pasamos al usuario."""
    ui.warn("En este momento no puedo confirmar el acceso al login desde aquí "
            "(puede necesitar navegador/sesión, o incluso SSH).")
    if assume_yes:
        return
    if not ui.ask_yes_no(
        f"¿Te abro {login_url} para que lo pruebes a mano con las credenciales guardadas en {session.loot}?",
        default=True,
    ):
        ui.warn("Siento no poder seguir ayudándote por ahora; lo mejoraré en próximas actualizaciones. :(")
        return
    _open_in_browser(login_url)
    ui.info(f"Las credenciales están guardadas en: {session.loot}")
    if ui.ask_yes_no("¿Ha funcionado alguna?", default=True):
        ui.flag("¡ENHORABUENA! Acceso conseguido. Genero el informe hasta este punto.")
        web_record["login_result"] = {"success": True, "manual": True, "url": login_url}
    else:
        ui.info("De acuerdo, lo dejamos aquí por ahora. Añadiré más vías de escalada en próximas versiones.")
        web_record["login_result"] = {"success": False, "manual": True, "url": login_url}


def _run_http(session: ReconSession, port: int, assume_yes: bool = False) -> None:
    from app.services import http_enum

    scan_data = session.scan_data
    target = scan_data.get("target", session.target)
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    ui.section("Enumeración web")
    fuzzer = http_enum.find_fuzzer()
    wordlist = http_enum.find_wordlist()
    if not fuzzer:
        ui.warn("No hay ffuf/gobuster/feroxbuster instalados. Pasos manuales:")
        for c in (f"whatweb {base}", f"gobuster dir -u {base} -w /usr/share/wordlists/dirb/common.txt"):
            ui.bullet(c)
            session.log_command(c, note="playbook http (manual)")
        return

    ui.info(f"Lanzando {fuzzer} contra {base} (con extensiones .php,.txt,.html)...")
    enum = http_enum.run_dir_enum(base, wordlist=wordlist)
    if enum.get("command"):
        session.log_command(enum["command"], note="fuzzing web")
    if enum.get("raw"):
        (session.loot / "fuzz.txt").write_text(enum["raw"][:200000], encoding="utf-8")
    if enum.get("error"):
        ui.warn(enum["error"])

    hits = enum.get("hits", [])
    if not hits:
        ui.warn("El fuzzing no devolvió rutas. Prueba otro diccionario o herramienta.")
        scan_data["web_enum"] = {"base": base, "tool": enum.get("tool"), "hits": [], "login": None}
        return

    ui.ok(f"{len(hits)} ruta(s) encontrada(s) con {enum.get('tool')}:")
    for h in hits[:30]:
        ui.bullet(f"/{h['path']}  (HTTP {h['status']}, {h['size']} bytes)")

    interesting = http_enum.interesting_hits(hits)
    login_paths = http_enum.find_login_paths(hits)
    if interesting:
        ui.section("Rutas interesantes")
        for h in interesting:
            ui.bullet(f"/{h['path']}  (HTTP {h['status']})")

    web_record = {"base": base, "tool": enum.get("tool"), "hits": hits,
                  "interesting": [h["path"] for h in interesting], "login": None, "login_result": None}

    # Atar cabos: si hay login, probar las credenciales del FTP (+ típicas).
    if login_paths:
        login_url = f"{base}/{login_paths[0]}"
        ui.ok(f"Login encontrado: {login_url}")
        n_u, n_p = len(session.creds["users"]), len(session.creds["passwords"])
        if session.has_creds():
            prompt = (f"¿Probamos una conexión al login con las credenciales encontradas "
                      f"({n_u}×{n_p}) y algunas típicas?")
        else:
            prompt = "¿Probamos una conexión al login con credenciales típicas (admin/admin, etc.)?"

        if assume_yes or ui.ask_yes_no(prompt, default=True):
            session.log_command(f"# probar credenciales en {login_url}", note="login web")
            lr = http_enum.try_login(login_url, session.creds["users"], session.creds["passwords"])
            web_record["login"] = login_url
            web_record["login_result"] = lr
            if lr.get("success"):
                ui.flag(f"Conexión al login OK en {login_url} → {lr['user']} : {lr['password']}  ({lr.get('evidence', '')})")
                ui.recommend(f"Entra en {login_url} con esas credenciales para el panel/flag.")
            else:
                _manual_login_fallback(session, login_url, assume_yes, web_record)
        else:
            web_record["login"] = login_url

    scan_data["web_enum"] = web_record


# ---------------------------------------------------------------------------
# Informe y cierre
# ---------------------------------------------------------------------------

def _write_reports(session: ReconSession, auditor: str, want_docx: bool) -> list[Path]:
    from app.services.report_content import safe_target

    scan_data = session.scan_data
    out_dir = session.dir / "InfoAuditoria"
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{safe_target(scan_data.get('target', session.target))}_{datetime.now():%Y%m%d_%H%M}"
    written: list[Path] = []

    md_path = out_dir / f"transcripcion_{tag}.md"
    md_path.write_text(build_transcript(session, auditor=auditor), encoding="utf-8")
    written.append(md_path)

    if want_docx:
        try:
            from app.services.report_generator import generate_audit_report
            docx_path = out_dir / f"informe_pentest_{tag}.docx"
            docx_path.write_bytes(generate_audit_report(scan_data, auditor=auditor))
            written.append(docx_path)
        except Exception as exc:
            ui.warn(f"No se pudo generar el .docx (queda la transcripción .md): {exc}")
    return written


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

    base_dir = Path(report_dir) if report_dir else _invoking_base_dir()
    session = ReconSession(target, base_dir)
    ui.section(f"Objetivo: {target}")
    ui.ok(f"Carpeta de trabajo: {session.dir}")
    ui.info("Lanzando reconocimiento pasivo (nmap + CVE + OSINT)...")

    try:
        from app.services.scan_pipeline import run_passive_recon
        scan_data = run_passive_recon(target)
    except Exception as exc:
        ui.err(f"No se pudo completar el recon: {exc}")
        return 1

    session.scan_data = scan_data
    if scan_data.get("error"):
        ui.err(f"nmap devolvió error: {scan_data['error']}")
        _write_scan_files(session)
        _chown_tree_to_invoker(session.dir)
        return 1

    _write_scan_files(session)
    ui.ok(f"Scan guardado en {session.dir / 'scan.txt'}")
    _show_findings(scan_data)

    if not do_exploit:
        ui.info("Modo solo-recon: no se ejecuta ningún vector.")
    else:
        options = _build_options(scan_data)
        if not options:
            ui.warn("No hay vector automático conocido para estos puertos.")
        else:
            ui.recommend(_recommendation_text({o["id"] for o in options}))
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
                    _run_http(session, _port_for(scan_data, "http_enum", 80), assume_yes=assume_yes)
                else:
                    _run_known_vector(session, choice["id"])

                if assume_yes:
                    break
                got_flag = scan_data.get("exploitation", {}).get("flag_captured", False)
                remaining_after = [o for o in options if o["id"] not in tried]
                if got_flag:
                    if ui.ask_yes_no("¿Finalizar y generar el informe?", default=True):
                        break
                elif not remaining_after:
                    ui.info("No quedan más vectores por probar.")
                    break
                elif not ui.ask_yes_no("¿Seguimos con el siguiente vector?", default=True):
                    break

    ui.section("Informe")
    written = _write_reports(session, auditor, want_docx)
    for p in written:
        ui.ok(f"Guardado: {p}")
    _chown_tree_to_invoker(session.dir)

    ui.section("Fin")
    ui.ok(f"Todo el trabajo queda en: {session.dir}")
    ui.info("La carpeta se conserva (scan, loot, informes) por si quieres seguir a mano.")
    return 0


def _run_known_vector(session: ReconSession, vector_id: str) -> None:
    """Telnet / SMB: reutiliza el motor de explotación del backend."""
    from app.services.exploit_runner import run_exploitation_checks
    from app.services.playbook_advisor import build_playbook_analysis
    from app.services.step_capture import capture_all_evidence

    scan_data = session.scan_data
    target = scan_data.get("target", session.target)
    operational = {"vector_id": vector_id, "source": "user",
                   "reason": "Vector elegido por el usuario en el CLI", "confidence": "high"}

    ui.info(f"Ejecutando módulo: {VECTOR_LABELS.get(vector_id, vector_id)}")
    result = run_exploitation_checks(target, scan_data, vector_id=vector_id, operational=operational)
    scan_data["exploitation"] = result
    scan_data["ai_analysis"] = build_playbook_analysis(target, scan_data, result)
    scan_data["phase"] = "active"
    for cmd in result.get("playbook_steps", []):
        session.log_command(cmd, note="playbook " + vector_id)
    for attempt in result.get("attempts", []):
        for step in attempt.get("steps", []):
            (ui.err if step.get("status") == "error" else ui.bullet)(f"[{step.get('action')}] {step.get('detail')}")
    if result.get("flag_captured"):
        for f in result.get("flags", []):
            ui.flag(f"{f['filename']}: {f['content']}")
        try:
            capture_all_evidence(scan_data)
        except Exception as exc:
            ui.warn(f"No se pudieron generar capturas: {exc}")
    else:
        ui.warn(result.get("message", "Sin flag en este vector."))
