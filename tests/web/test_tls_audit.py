import datetime

import pytest

from web import tls_audit


@pytest.mark.parametrize("raw,host,port", [
    ("example.com", "example.com", 443),
    ("https://example.com/path", "example.com", 443),
    ("example.com:8443", "example.com", 8443),
    ("http://example.com:80/x", "example.com", 80),
])
def test_parse_host_port(raw, host, port):
    assert tls_audit._parse_host_port(raw) == (host, port)


def test_main_no_args_returns_2(capsys):
    assert tls_audit.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_parse_der_none():
    info = tls_audit._parse_der(None)
    assert info["subject"] == "" and info["days_to_expiry"] is None


def test_derive_findings_ranks_and_flags():
    cert = {"expired": True, "not_after": "2015-01-01", "valid_chain": False,
            "validation_error": "expired", "self_signed": False, "days_to_expiry": -100}
    versions = {"deprecated_accepted": ["TLSv1.0"]}
    headers = {"missing": [{"header": "strict-transport-security", "why": "HSTS"},
                           {"header": "referrer-policy", "why": "ref"}],
               "http_upgrades_to_https": False}
    findings = tls_audit._derive_findings(cert, versions, headers)
    levels = [f["level"] for f in findings]
    assert levels[0] == "high"                       # most severe first
    assert any("EXPIRED" in f["note"] for f in findings)
    assert any("TLSv1.0" in f["note"] for f in findings)
    assert any("does not redirect" in f["note"] for f in findings)


def test_parse_der_roundtrip_self_signed():
    """Generate a self-signed cert and confirm the DER parser reads its fields."""
    crypto = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)         # self-signed: subject == issuer
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("unit.test")]), False)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding
    info = tls_audit._parse_der(cert.public_bytes(Encoding.DER))
    assert info["subject"] == "unit.test"
    assert info["self_signed"] is True
    assert info["sans"] == ["unit.test"]
    assert 28 <= info["days_to_expiry"] <= 30
    assert info["expired"] is False


@pytest.mark.network
def test_run_live_valid_host():
    res = tls_audit.run("example.com", version_probe=False)
    assert res["cert"]["valid_chain"] is True
    assert res["cert"]["negotiated_version"].startswith("TLS")
