"""Map an OAuth 2.0 / OpenID Connect deployment and flag classic weaknesses.

Given an issuer (or its ``.well-known/openid-configuration`` URL), this pulls the
discovery document, lays out the endpoints and supported flows/scopes, and flags the
config-level problems an attacker cares about: the implicit flow being enabled
(tokens leak via URL/history), missing/weak PKCE, ``none`` client auth, and the like.
The tedious "read the discovery doc and know what's dangerous" step, done for you.

Dependencies: standard library only. No external API.

Safety: read-only. Fetches a public discovery document. Only test deployments you're
authorized to.

Usage:
    python -m web.oauth https://issuer.example.com
    python -m web.oauth https://issuer.example.com/.well-known/openid-configuration --json
"""

from __future__ import annotations

import argparse
import sys

from common import http
from common.output import emit, log


def _discovery_url(target: str) -> str:
    if ".well-known" in target:
        return target
    return target.rstrip("/") + "/.well-known/openid-configuration"


def run(target: str, *, timeout: float = 15.0) -> dict:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    url = _discovery_url(target)
    log(f"[*] fetching {url} ...")
    r = http.get(url, timeout=timeout, retries=1)
    if not r.ok:
        return {"target": target, "discovery_url": url, "ok": False,
                "error": r.error or f"HTTP {r.status}", "findings": []}
    try:
        doc = r.json()
    except ValueError:
        return {"target": target, "discovery_url": url, "ok": False,
                "error": "discovery document is not JSON", "findings": []}

    endpoints = {k: doc[k] for k in (
        "issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
        "jwks_uri", "registration_endpoint", "revocation_endpoint",
        "end_session_endpoint", "introspection_endpoint") if k in doc}
    response_types = doc.get("response_types_supported", [])
    grant_types = doc.get("grant_types_supported", [])
    scopes = doc.get("scopes_supported", [])
    pkce = doc.get("code_challenge_methods_supported", [])
    token_auth = doc.get("token_endpoint_auth_methods_supported", [])

    findings = []

    def flag(level, note):
        findings.append({"level": level, "note": note})

    if any("token" in rt for rt in response_types):
        flag("medium", "implicit flow enabled (response_type includes 'token'/'id_token') "
                       "— access tokens leak via redirect URL / browser history")
    if not pkce:
        flag("medium", "no code_challenge_methods_supported — PKCE not advertised "
                       "(public clients vulnerable to auth-code interception)")
    elif "S256" not in pkce:
        flag("medium", f"PKCE only supports {pkce} (no S256) — weak")
    if "none" in token_auth:
        flag("medium", "token endpoint allows 'none' client auth (unauthenticated clients)")
    if "registration_endpoint" in endpoints:
        flag("info", "dynamic client registration is open — enumerate/abuse if unauthenticated")
    if endpoints.get("authorization_endpoint", "").startswith("http://"):
        flag("high", "authorization endpoint is plain HTTP")
    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["level"], 3))

    return {"target": target, "discovery_url": url, "ok": True,
            "endpoints": endpoints, "response_types": response_types,
            "grant_types": grant_types, "scopes": scopes, "pkce": pkce,
            "token_endpoint_auth": token_auth, "findings": findings}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# oauth: {res['target']}"]
    if not res["ok"]:
        lines.append(f"# error: {res['error']}")
        return lines
    lines.append("## endpoints")
    lines += [f"  {k}: {v}" for k, v in res["endpoints"].items()]
    lines.append(f"# response_types: {', '.join(res['response_types'])}")
    lines.append(f"# grant_types: {', '.join(res['grant_types'])}")
    lines.append(f"# PKCE: {', '.join(res['pkce']) or 'NONE'}")
    if res["scopes"]:
        lines.append(f"# scopes: {', '.join(res['scopes'][:30])}")
    lines.append("## FINDINGS")
    lines += [f"[{f['level'].upper()}] {f['note']}" for f in res["findings"]] or ["(none)"]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.oauth", description="Map an OAuth/OIDC deployment and flag weaknesses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python -m web.oauth https://issuer.example.com\n")
    p.add_argument("target", nargs="?", help="Issuer base URL or discovery URL.")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.target, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
