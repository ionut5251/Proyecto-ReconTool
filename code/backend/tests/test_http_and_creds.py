"""Pruebas de la enumeración web (parseo) y del encadenado de credenciales FTP."""

import tempfile
from pathlib import Path

from app.services import http_enum
from app.services.ftp_probe import classify_filename, parse_credential_lists


# -- FTP: reconocer listas de credenciales por nombre ------------------------

def test_classify_credential_lists_by_name():
    assert "credential" in classify_filename("allowed.userlist")
    assert "credential" in classify_filename("allowed.userlist.passwd")
    assert "credential" in classify_filename("users.bak")
    assert classify_filename("index.html") == []  # html no es interesante


def test_parse_credential_lists_splits_users_and_passwords():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "allowed.userlist").write_text("aesc\nlevi\nadmin\n")
        Path(d, "allowed.userlist.passwd").write_text("manchester\nliverpool\n")
        users, passwords = parse_credential_lists(d)
        assert users == ["aesc", "levi", "admin"]
        assert passwords == ["manchester", "liverpool"]


# -- HTTP: parseo de salidas de fuzzers --------------------------------------

def test_parse_ffuf_output():
    out = """
dashboard               [Status: 301, Size: 316, Words: 20, Lines: 10]
login.php               [Status: 200, Size: 1200, Words: 50, Lines: 30]
FUZZ                    [Status: 200, Size: 1, Words: 1, Lines: 1]
"""
    hits = http_enum._parse_hits("ffuf", out, "http://10.10.10.10")
    paths = {h["path"] for h in hits}
    assert "dashboard" in paths and "login.php" in paths
    assert "FUZZ" not in paths


def test_parse_gobuster_output():
    out = "/login.php           (Status: 200) [Size: 1200]\n/admin               (Status: 301) [Size: 0]\n"
    hits = http_enum._parse_hits("gobuster", out, "http://10.10.10.10")
    paths = {h["path"] for h in hits}
    assert "login.php" in paths and "admin" in paths


def test_interesting_and_login_detection():
    hits = [{"path": "css", "status": 301, "size": 0},
            {"path": "login.php", "status": 200, "size": 1200},
            {"path": "dashboard", "status": 301, "size": 0}]
    interesting = {h["path"] for h in http_enum.interesting_hits(hits)}
    assert "login.php" in interesting and "dashboard" in interesting and "css" not in interesting
    assert http_enum.find_login_paths(hits) == ["login.php"]


def test_guess_fields():
    html = '<form><input name="username"><input type="password" name="password"></form>'
    u, p = http_enum._guess_fields(html)
    assert u == "username" and p == "password"


def test_parse_hits_strips_ansi():
    # ffuf colorea la salida; el path NO debe llevar códigos ANSI (bug del \x1b en la URL)
    out = "\x1b[32mlogin.php\x1b[0m   [Status: 200, Size: 1577]\n"
    hits = http_enum._parse_hits("ffuf", out, "http://10.129.30.17")
    assert hits[0]["path"] == "login.php"


def test_clean_removes_ansi_and_blanks():
    assert http_enum._clean(["\x1b[31madmin\x1b[0m", " root ", "", "a" * 200]) == ["admin", "root"]


def test_try_ftp_login_without_creds():
    from app.services.ftp_probe import try_ftp_login
    r = try_ftp_login("127.0.0.1", [], [])
    assert r["success"] is False and r["error"]
