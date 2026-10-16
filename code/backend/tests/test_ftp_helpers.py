"""Pruebas de los helpers de enumeración FTP (funciones puras, sin red)."""

from app.services.ftp_probe import (
    build_ftp_recommendations,
    classify_filename,
    scan_text_for_secrets,
)


def test_classify_flag_files():
    assert classify_filename("flag.txt") == ["flag"]
    assert classify_filename("user.txt") == ["flag"]
    assert classify_filename("root.txt") == ["flag"]


def test_classify_credentials_and_keys():
    assert "credential" in classify_filename("wp-config.php")
    assert "key" in classify_filename("id_rsa")
    assert "key" in classify_filename("backup.pem")


def test_classify_interesting_and_boring():
    assert classify_filename("dump.sql") == ["interesting"]
    assert classify_filename("photo.png") == []


def test_flag_file_hex_is_not_a_hash():
    # En un flag.txt, el hex de 32 es la FLAG, no un hash a crackear.
    findings = scan_text_for_secrets("flag.txt", "d41d8cd98f00b204e9800998ecf8427e\n")
    assert not any(f["type"] == "hash" for f in findings)


def test_detects_unix_crypt_hash():
    findings = scan_text_for_secrets("shadow.bak", "root:$6$abc$DEFghi0123456789:19000:0:99999:7:::")
    assert any(f["type"] == "hash" and f["sample"].startswith("$6$") for f in findings)


def test_detects_private_key():
    findings = scan_text_for_secrets("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")
    assert any(f["type"] == "private_key" for f in findings)


def test_detects_credentials():
    findings = scan_text_for_secrets("config.php", "define('DB_PASSWORD', 'S3cr3t!');")
    assert any(f["type"] == "credential" for f in findings)


def test_recommendation_for_hash_mentions_john_and_wordlist():
    findings = scan_text_for_secrets("shadow.bak", "root:$6$abc$DEF0123456789:19000:0:99999:7:::")
    recs = build_ftp_recommendations(findings, [], "10.10.10.5")
    joined = " ".join(recs).lower()
    assert "sha512crypt" in joined
    assert "rockyou" in joined


def test_recommendation_for_private_key_mentions_ssh():
    findings = scan_text_for_secrets("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nx\n")
    recs = build_ftp_recommendations(findings, [], "10.10.10.5")
    assert any("ssh -i" in r for r in recs)
