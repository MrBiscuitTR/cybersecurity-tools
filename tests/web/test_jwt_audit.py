import json

import pytest

from web import jwt_audit as J


def test_b64url_roundtrip():
    assert J.b64url_decode(J.b64url_encode(b"\x00\xffabc")) == b"\x00\xffabc"


def test_split_rejects_bad():
    with pytest.raises(ValueError):
        J.split("only.two")


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hs_sign_verify(alg):
    tok = J.sign({}, {"user": "admin"}, "secret", alg)
    assert J.verify(tok, "secret")["valid"] is True
    assert J.verify(tok, "wrong")["valid"] is False


def test_none_alg():
    tok = J.sign({}, {"user": "admin"}, "", "none")
    assert tok.endswith(".")
    assert J.verify(tok, "")["valid"] is True


def _pems(priv):
    from cryptography.hazmat.primitives import serialization as S
    return (priv.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()),
            priv.public_key().public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo))


def test_rs_and_ps_roundtrip():
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv, pub = _pems(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    for alg in ("RS256", "PS256", "RS512"):
        assert J.verify(J.sign({}, {"a": 1}, priv, alg), pub)["valid"] is True


def test_es_and_eddsa_roundtrip():
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    priv, pub = _pems(ec.generate_private_key(ec.SECP256R1()))
    assert J.verify(J.sign({}, {"a": 1}, priv, "ES256"), pub)["valid"] is True
    dpriv, dpub = _pems(ed25519.Ed25519PrivateKey.generate())
    assert J.verify(J.sign({}, {"a": 1}, dpriv, "EdDSA"), dpub)["valid"] is True


def test_analyze_findings():
    tok = J.sign({"kid": "../etc", "jku": "http://evil"}, {"user": "x"}, "k", "HS256")
    findings = J.analyze(tok)["findings"]
    notes = " ".join(f["note"] for f in findings)
    assert "jku" in notes and "kid" in notes and "exp" in notes
    assert findings[0]["level"] == "high"          # ranked, jku first


def test_crack_hs():
    tok = J.sign({}, {"u": 1}, "hunter2", "HS256")
    assert J.crack_hs(tok, ["a", "hunter2", "b"]) == "hunter2"
    assert J.crack_hs(tok, ["a", "b"]) is None


def test_attack_none_and_confusion():
    from cryptography.hazmat.primitives.asymmetric import rsa
    _, pub = _pems(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    tok = J.sign({}, {"user": "admin"}, "weak", "HS256")
    res = J.attack(tok, public_key=pub, words=["x", "weak"])
    kinds = {a["attack"] for a in res["attacks"]}
    assert any("alg-none" == k for k in kinds)
    assert any("confusion" in k for k in kinds)
    assert any(a.get("secret") == "weak" for a in res["attacks"])
    # forged 'none' token should verify as unsigned.
    none_tok = next(a["token"] for a in res["attacks"] if a["attack"] == "alg-none"
                    and a["variant"] == "none")
    assert J.verify(none_tok, "")["valid"] is True


def test_main_no_action_returns_2(capsys):
    assert J.main([]) == 2


def test_main_decode_bad_token_returns_1(capsys):
    assert J.main(["decode", "not.a.token.x"]) == 1
    assert "error" in capsys.readouterr().err.lower()
