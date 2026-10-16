"""Pruebas de la detección y priorización de vectores."""

from app.services.service_router import detect_attack_vectors


def _scan(*ports_services):
    return {
        "target": "10.10.10.10",
        "results": [
            {"host": "10.10.10.10", "port": p, "state": "open", "service": s,
             "product": "", "version": "", "cve_findings": []}
            for p, s in ports_services
        ],
        "os": [],
    }


def test_detects_ftp_vector():
    plan = detect_attack_vectors(_scan((21, "ftp")))
    assert any(v["id"] == "ftp_anonymous" for v in plan["vectors"])
    assert plan["primary"]["id"] == "ftp_anonymous"


def test_ftp_prioritized_over_http():
    plan = detect_attack_vectors(_scan((21, "ftp"), (80, "http")))
    ids = {v["id"] for v in plan["vectors"]}
    assert {"ftp_anonymous", "http_enum"} <= ids
    assert plan["primary"]["id"] == "ftp_anonymous"


def test_telnet_has_highest_priority():
    plan = detect_attack_vectors(_scan((21, "ftp"), (23, "telnet"), (445, "microsoft-ds")))
    assert plan["primary"]["id"] == "telnet_root_blank"


def test_no_vector_when_no_known_ports():
    plan = detect_attack_vectors(_scan((3306, "mysql")))
    assert plan["primary"] is None
