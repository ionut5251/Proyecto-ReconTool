"""Pruebas de la sesión efímera y de la generación de informe/transcripción."""

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


def test_session_creates_and_cleans_up():
    s = ReconSession("10.10.10.5")
    d = s.dir
    assert d.is_dir() and s.screenshots.is_dir() and s.loot.is_dir()
    s.cleanup()
    assert not d.exists()


def test_session_redirects_screenshots_dir():
    import app.services.step_capture as sc
    s = ReconSession("10.10.10.5")
    try:
        assert sc.SCREENSHOTS_DIR == s.screenshots
    finally:
        s.cleanup()


def test_transcript_contains_commands_and_flag():
    s = ReconSession("10.10.10.5")
    try:
        s.scan_data = _scan_with_flag()
        s.log_command("ftp 10.10.10.5", note="ftp")
        md = build_transcript(s, auditor="Constan")
        assert "HTB{demo}" in md
        assert "ftp 10.10.10.5" in md
        assert "Comandos ejecutados" in md
    finally:
        s.cleanup()


def test_docx_report_is_generated():
    scan = _scan_with_flag()
    data = generate_audit_report(scan, auditor="Constan")
    assert isinstance(data, (bytes, bytearray))
    assert len(data) > 5000
