"""Audit a host's TLS configuration and HTTP security headers in one call.

For a target ``host[:port]`` this reports:
  - the negotiated TLS (protocol version, cipher, and — by probing — which
    protocol versions the server accepts, flagging deprecated TLS 1.0/1.1),
  - the leaf certificate (subject, issuer, SANs, validity window, days-to-expiry,
    and whether it's expired / not-yet-valid / self-signed-looking),
  - HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy) with a note on what's missing/weak,
  - redirect behavior (does plain HTTP upgrade to HTTPS?).

This is the kind of audit that's tedious by hand (openssl s_client + curl -I with
a dozen flags) and perfect to hand an LLM as a single structured result.

Dependencies: standard library (``ssl``, ``socket``, urllib) plus ``cryptography``
to parse the leaf certificate's fields (Python's ``getpeercert`` returns nothing
for a cert that doesn't validate, and we specifically want to inspect bad ones).
No external API. Connects directly to the target over TLS/HTTP.

Safety: read-only. Opens TLS/HTTP connections and reads certs/headers. Sends no
payloads, changes nothing. Standard, non-intrusive — but still only run it against
hosts you're authorized to test.

Usage:
    python -m web.tls_audit example.com
    python -m web.tls_audit example.com:8443 --json
    python -m web.tls_audit example.com --no-version-probe   # faster, skip probing
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone

from common import http
from common.output import emit, log

# Security headers we check, with why each matters (surfaced in output).
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS: forces HTTPS; prevents SSL-strip",
    "content-security-policy": "CSP: mitigates XSS / injection",
    "x-frame-options": "clickjacking protection (or use CSP frame-ancestors)",
    "x-content-type-options": "nosniff: stops MIME-type confusion",
    "referrer-policy": "controls Referer leakage",
    "permissions-policy": "restricts powerful browser features",
}

# Protocol versions to probe for support. TLS 1.0/1.1 are deprecated; SSLv3 dead.
_PROBE_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
_DEPRECATED = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_host_port(target: str, default_port: int = 443) -> tuple[str, int]:
    t = target.strip()
    if t.startswith(("http://", "https://")):
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if ":" in t and t.count(":") == 1:  # host:port (ignore IPv6 for simplicity)
        host, _, port = t.partition(":")
        return host, int(port) if port.isdigit() else default_port
    return t, default_port


def _get_der_and_negotiated(host: str, port: int, timeout: float) -> dict:
    """Connect once with a permissive context to read the cert (as DER) and the
    negotiated version/cipher, even if the cert is invalid — we want to *report*
    invalidity, not just fail on it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect, don't enforce
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            return {"version": ss.version(), "cipher": ss.cipher(),
                    "der": ss.getpeercert(binary_form=True)}


def _cert_info(host: str, port: int, timeout: float) -> dict:
    """Get validation status (strict context) plus the actual cert fields
    (parsed from DER with cryptography, so invalid/expired certs still report)."""
    result: dict = {"valid_chain": None, "validation_error": None}
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with vctx.wrap_socket(s, server_hostname=host):
                result["valid_chain"] = True
    except ssl.SSLCertVerificationError as exc:
        result["valid_chain"] = False
        result["validation_error"] = str(exc).split("(", 1)[0].strip()
    except (OSError, ssl.SSLError) as exc:
        result["validation_error"] = f"{type(exc).__name__}: {exc}"

    info = _get_der_and_negotiated(host, port, timeout)
    result["negotiated_version"] = info["version"]
    result["negotiated_cipher"] = info["cipher"][0] if info["cipher"] else None
    result.update(_parse_der(info["der"]))
    return result


def _parse_der(der: bytes | None) -> dict:
    """Extract subject/issuer/SANs/validity from a DER cert using cryptography."""
    empty = {"subject": "", "issuer": "", "sans": [], "not_before": None,
             "not_after": None, "days_to_expiry": None, "expired": None, "self_signed": None}
    if not der:
        return empty
    try:
        from cryptography import x509
    except ImportError:
        return empty  # cryptography not installed; degrade rather than crash
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return empty
    subject = _common_name(cert.subject)
    issuer = _common_name(cert.issuer)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    # cryptography >= 42 exposes tz-aware *_utc; fall back for older versions.
    not_after_dt = getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before_dt = getattr(cert, "not_valid_before_utc", None) or \
        cert.not_valid_before.replace(tzinfo=timezone.utc)
    days_left = (not_after_dt - datetime.now(timezone.utc)).days
    return {
        "subject": subject, "issuer": issuer, "sans": sans,
        "not_before": not_before_dt.strftime("%Y-%m-%d"),
        "not_after": not_after_dt.strftime("%Y-%m-%d"),
        "days_to_expiry": days_left,
        "expired": days_left < 0,
        "self_signed": bool(subject and subject == issuer),
    }


def _common_name(name) -> str:
    from cryptography.x509.oid import NameOID
    cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cns:
        return cns[0].value
    orgs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return orgs[0].value if orgs else ""


def _probe_versions(host: str, port: int, timeout: float) -> dict:
    """Try to negotiate each protocol version; record which the server accepts."""
    accepted, deprecated_ok = [], []
    for label, ver in _PROBE_VERSIONS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except ValueError:
            continue  # this Python/OpenSSL can't pin that version
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    accepted.append(label)
                    if label in _DEPRECATED:
                        deprecated_ok.append(label)
        except (ssl.SSLError, OSError):
            pass
    return {"accepted": accepted, "deprecated_accepted": deprecated_ok}


def _headers(host: str, port: int) -> dict:
    """Fetch HTTPS headers and check the security set; note HTTP->HTTPS upgrade."""
    scheme = "https"
    url = f"{scheme}://{host}{'' if port == 443 else f':{port}'}/"
    r = http.get(url, timeout=12, retries=1)
    present, missing = {}, []
    hdrs = {}
    if r.ok or r.status:
        # Re-fetch raw headers: http.get doesn't expose them, so do a light urllib call.
        hdrs = _raw_headers(url)
    for name, why in SECURITY_HEADERS.items():
        if name in hdrs:
            present[name] = hdrs[name]
        else:
            missing.append({"header": name, "why": why})
    # Does plain HTTP redirect to HTTPS?
    http_upgrade = _http_upgrades(host)
    return {"status": r.status, "server": hdrs.get("server", ""),
            "present": present, "missing": missing, "http_upgrades_to_https": http_upgrade}


def _raw_headers(url: str) -> dict[str, str]:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": http.DEFAULT_UA})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:  # HTTPError still carries headers
        hdrs = getattr(exc, "headers", None)
        return {k.lower(): v for k, v in hdrs.items()} if hdrs else {}


def _http_upgrades(host: str) -> bool | None:
    import urllib.request
    try:
        req = urllib.request.Request(f"http://{host}/", headers={"User-Agent": http.DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.url.startswith("https://")
    except Exception:
        return None


def run(target: str, *, timeout: float = 10.0, version_probe: bool = True) -> dict:
    """Audit TLS + headers for ``target`` (host or host:port).

    Returns a dict with keys: host, port, tls, cert, versions, headers, findings.
    ``findings`` is a ranked list of {level, note} the operator should read first.
    """
    host, port = _parse_host_port(target)
    log(f"[*] TLS handshake {host}:{port} ...")
    cert = _cert_info(host, port, timeout)
    versions = _probe_versions(host, port, timeout) if version_probe else {}
    log(f"[*] fetching headers for {host} ...")
    headers = _headers(host, port)
    findings = _derive_findings(cert, versions, headers)
    return {"host": host, "port": port, "cert": cert,
            "versions": versions, "headers": headers, "findings": findings}


def _derive_findings(cert: dict, versions: dict, headers: dict) -> list[dict]:
    """Boil the raw data down to the things worth flagging, most severe first."""
    out: list[dict] = []
    if cert.get("expired"):
        out.append({"level": "high", "note": f"certificate EXPIRED ({cert['not_after']})"})
    elif cert.get("days_to_expiry") is not None and cert["days_to_expiry"] < 21:
        out.append({"level": "medium", "note": f"cert expires in {cert['days_to_expiry']} days"})
    if cert.get("valid_chain") is False:
        out.append({"level": "high", "note": f"cert does NOT validate: {cert.get('validation_error')}"})
    if cert.get("self_signed"):
        out.append({"level": "medium", "note": "certificate appears self-signed"})
    for dep in versions.get("deprecated_accepted", []):
        out.append({"level": "medium", "note": f"deprecated {dep} accepted"})
    for m in headers.get("missing", []):
        lvl = "medium" if m["header"] in ("strict-transport-security", "content-security-policy") else "low"
        out.append({"level": lvl, "note": f"missing header {m['header']} ({m['why']})"})
    if headers.get("http_upgrades_to_https") is False:
        out.append({"level": "medium", "note": "plain HTTP does not redirect to HTTPS"})
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda f: order.get(f["level"], 3))
    return out


def _compact_lines(res: dict) -> list[str]:
    c, v, h = res["cert"], res["versions"], res["headers"]
    lines = [f"# tls audit: {res['host']}:{res['port']}"]
    lines.append(f"# negotiated: {c.get('negotiated_version')} {c.get('negotiated_cipher')}")
    if v:
        lines.append(f"# versions accepted: {', '.join(v.get('accepted', [])) or 'none'}")
    lines.append(f"# cert: subject={c.get('subject')!r} issuer={c.get('issuer')!r} "
                 f"expires={c.get('not_after')} ({c.get('days_to_expiry')}d) "
                 f"valid_chain={c.get('valid_chain')}")
    if c.get("sans"):
        lines.append("# SANs: " + ", ".join(c["sans"][:30]))
    lines.append(f"# server: {h.get('server','')!r}  http->https: {h.get('http_upgrades_to_https')}")
    if h.get("present"):
        lines.append("## security headers present")
        lines += [f"{k}: {val}" for k, val in h["present"].items()]
    lines.append("## FINDINGS")
    lines += [f"[{f['level'].upper()}] {f['note']}" for f in res["findings"]] or ["(none)"]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.tls_audit",
        description="Audit TLS config + HTTP security headers for a host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m web.tls_audit example.com\n"
            "  python -m web.tls_audit example.com:8443 --json\n"
            "  python -m web.tls_audit example.com --no-version-probe\n"
        ),
    )
    p.add_argument("target", nargs="?", help="Host or host:port (default port 443).")
    p.add_argument("--no-version-probe", action="store_true",
                   help="Skip probing individual TLS versions (faster).")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-connection timeout (s).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.target, timeout=args.timeout, version_probe=not args.no_version_probe)
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
