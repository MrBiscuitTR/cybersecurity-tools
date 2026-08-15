"""Test a URL for CORS misconfigurations that let another origin read responses.

Sends requests with a series of crafted ``Origin`` headers and inspects the
``Access-Control-Allow-Origin`` (ACAO) / ``Access-Control-Allow-Credentials`` (ACAC)
responses to detect the classic bugs: arbitrary-origin reflection, ``null`` origin
trust, prefix/suffix/subdomain matching bypasses, and wildcard-with-credentials —
each of which can let an attacker's page read authenticated responses.

Dependencies: standard library only. No external API.

Safety: read-only. Sends benign GETs with different Origin headers; nothing else.
Only test targets you're authorized to.

Usage:
    python -m web.cors https://api.example.com/me
    python -m web.cors https://api.example.com/me --json
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from urllib.parse import urlparse

from common import http
from common.output import emit, log


def _probe(url: str, origin: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"Origin": origin, "User-Agent": http.DEFAULT_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            h = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        h = {k.lower(): v for k, v in getattr(exc, "headers", {}).items()} \
            if getattr(exc, "headers", None) else {}
    return {"origin": origin,
            "acao": h.get("access-control-allow-origin", ""),
            "acac": h.get("access-control-allow-credentials", "").lower() == "true"}


def run(url: str, *, timeout: float = 12.0) -> dict:
    host = urlparse(url).netloc
    base_domain = host.split(":")[0]
    tests = {
        "arbitrary": "https://evil-attacker-cors-test.com",
        "null": "null",
        "prefix": f"https://{base_domain}.evil-attacker.com",
        "suffix": f"https://evil{base_domain}",
        "subdomain": f"https://evil.{base_domain}",
        "not-https": f"http://{base_domain}",
    }
    log(f"[*] probing CORS on {url} with {len(tests)} origins ...")
    results = {name: _probe(url, origin, timeout) for name, origin in tests.items()}

    findings = []
    for name, r in results.items():
        acao, acac, origin = r["acao"], r["acac"], r["origin"]
        reflected = acao == origin
        if reflected and acac:
            findings.append({"level": "high",
                             "note": f"{name}: reflects Origin '{origin}' AND allows credentials "
                                     f"-> attacker origin can read authenticated responses"})
        elif reflected:
            findings.append({"level": "medium",
                             "note": f"{name}: reflects arbitrary Origin '{origin}' (no creds)"})
        elif acao == "null" and origin == "null":
            findings.append({"level": "high" if acac else "medium",
                             "note": "trusts Origin 'null'"
                                     + (" WITH credentials" if acac else "")})
    if any(r["acao"] == "*" and r["acac"] for r in results.values()):
        findings.append({"level": "medium", "note": "wildcard ACAO with credentials (browser-blocked but a smell)"})
    order = {"high": 0, "medium": 1}
    findings.sort(key=lambda f: order.get(f["level"], 2))
    return {"url": url, "results": results, "findings": findings,
            "vulnerable": any(f["level"] == "high" for f in findings)}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# cors: {res['url']}  {'VULNERABLE' if res['vulnerable'] else 'no critical issues'}"]
    lines.append("## FINDINGS")
    lines += [f"[{f['level'].upper()}] {f['note']}" for f in res["findings"]] or ["(none)"]
    lines.append("## raw (origin -> ACAO, credentials)")
    lines += [f"  {r['origin']}  ->  {r['acao'] or '(none)'}  creds={r['acac']}"
              for r in res["results"].values()]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.cors", description="Detect CORS misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python -m web.cors https://api.example.com/me\n")
    p.add_argument("url", nargs="?", help="URL to test (ideally an authenticated API endpoint).")
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.url, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
