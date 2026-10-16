"""Pruebas de la sesión (carpeta por IP) y del informe/transcripción."""

import tempfile
from pathlib import Path

from app.cli.session import ReconSession
from app.cli.transcript import build_transcript
from app.services.playbook_advisor import build_playbook_analysis
from app.services.report_generator import generate_audit_report


def _scan_with_flag():
    scan = {
        "target": "10.10.10.5",
        "results": [
            {"host": "10.10.10.5", "port": 21, "state": "open", "service": "ftp",
             "product": "vsftpd", "version": "3.0.3", "cve_findings": []},
        ],
        "os": [],
    }
    scan["attack_plan"] = {
        "primary": {"id": "ftp_anonymous"},
        "vectors": [{"id": "ftp_anonymous", "port": 21, "title": "FTP", "summary": "ftp"}],
    }
    scan["exploitation"] = {
        "attempts": [{
            "module": "ftp_anonymous", "host": "10.10.10.5", "port": 21, "success": True,
            "steps": [{"action": "flag", "detail": "Flag en flag.txt", "status": "ok"}],
            "flags": [{"filename": "flag.txt", "content": "HTB{demo}"}],
        }],
        "flag_captured": True,
        "flags": [{"filename": "flag.txt", "content": "HTB{demo}"}],
        "vector_used": "ftp_anonymous",
    }
    scan["ai_analysis"] = build_playbook_analysis("10.10.10.5", scan, scan["exploitation"])
    return scan


def test_session_creates_persistent_per_ip_folder():
    with tempfile.TemporaryDirectory() as base:
        s = ReconSession("10.10.10.5", base)
        assert s.dir == Path(base) / "10.10.10.5"
        assert s.dir.is_dir() and s.loot.is_dir() and s.screenshots.is_dir()
        # context manager NO borra la carpeta
        with s:
            pass
        assert s.dir.exists(), "la carpeta por IP debe conservarse"


def test_session_redirects_screenshots_dir():
    import app.services.step_capture as sc
    with tempfile.TemporaryDirectory() as base:
        s = ReconSession("10.10.10.5", base)
        assert sc.SCREENSHOTS_DIR == s.screenshots


def test_session_credentials_store():
    with tempfile.TemporaryDirectory() as base:
        s = ReconSession("10.10.10.5", base)
        s.add_users(["admin", "admin", "root"])
        s.add_passwords(["x", "y"])
        assert s.creds["users"] == ["admin", "root"]
        assert s.has_creds()


def test_transcript_and_docx():
    with tempfile.TemporaryDirectory() as base:
        s = ReconSession("10.10.10.5", base)
        s.scan_data = _scan_with_flag()
        s.log_command("ftp 10.10.10.5", note="ftp")
        md = build_transcript(s, auditor="Constan")
        assert "HTB{demo}" in md and "ftp 10.10.10.5" in md
        data = generate_audit_report(s.scan_data, auditor="Constan")
        assert isinstance(data, (bytes, bytearray)) and len(data) > 5000
