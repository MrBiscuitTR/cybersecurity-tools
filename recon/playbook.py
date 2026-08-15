"""Run a full first-pass recon playbook on a domain in one call.

Chains the recon tools so an operator (or an autonomous agent) gets a single
prioritized picture instead of running five tools by hand: enumerate subdomains ->
probe them over HTTP(S) -> rank the live hosts by how interesting they look (auth
gates, dev/staging/admin/vault titles, odd stacks, broken origins) -> and mine the
apex's JavaScript for endpoints/secrets. Output is a ranked target list with reasons.

Dependencies: standard library (reuses recon.subdomains, recon.http_probe,
web.js_recon). No external API beyond those tools'.

Safety: read-only recon (passive enumeration + benign HTTP GETs). Only run against
domains you're authorized to test.

Usage:
    python -m recon.playbook example.com
    python -m recon.playbook example.com --json
"""

from __future__ import annotations

import argparse
import re
import sys

from common.output import emit, log
from common.validate import domain as norm_domain

_INTERESTING = re.compile(
    r"(?i)(admin|dashboard|login|portal|vault|secret|internal|dev|staging|test|"
    r"jenkins|grafana|kibana|phpmyadmin|gitlab|jira|vpn|api|backup|db|panel|"
    r"console|manage|status|monitor|debug)")


def _score(host_result: dict, apex: str) -> tuple[int, list[str]]:
    """Rank a live host: higher score = more worth looking at. Returns (score, reasons)."""
    score, reasons = 0, []
    status = host_result.get("status")
    title = host_result.get("title", "") or ""
    host = host_result["host"]
    server = host_result.get("server", "")

    if status in (401, 403):
        score += 30
        reasons.append(f"auth-gated ({status})")
    if status and 500 <= status < 600:
        score += 20
        reasons.append(f"broken origin ({status}) — possible takeover/dev box")
    m = _INTERESTING.search(host) or _INTERESTING.search(title)
    if m:
        score += 25
        reasons.append(f"interesting keyword '{m.group(0).lower()}'")
    if server and "cloudflare" not in server.lower():
        score += 5
        reasons.append(f"direct origin (server={server})")
    if host_result.get("tech"):
        score += 5
        reasons.append("tech: " + ",".join(host_result["tech"]))
    return score, reasons


def run(domain: str, *, timeout: float = 8.0) -> dict:
    from recon.http_probe import run as probe
    from recon.subdomains import run as enum
    from web.js_recon import run as jsrecon

    d = norm_domain(domain)
    log(f"[*] [1/3] enumerating subdomains of {d} ...")
    subs = enum(d)["subdomains"]
    hosts = sorted(set(subs) | {d})
    log(f"[*] [2/3] probing {len(hosts)} hosts ...")
    probed = probe(hosts, timeout=timeout)
    live = [r for r in probed["results"] if r["alive"]]

    ranked = []
    for r in live:
        score, reasons = _score(r, d)
        ranked.append({"host": r["host"], "url": r["url"], "status": r["status"],
                       "title": r["title"], "server": r["server"], "tech": r["tech"],
                       "score": score, "reasons": reasons})
    ranked.sort(key=lambda x: (-x["score"], x["host"]))

    log(f"[*] [3/3] mining JavaScript on https://{d} ...")
    try:
        js = jsrecon(f"https://{d}", timeout=timeout)
        js_summary = {"endpoints": len(js["endpoints"]), "secrets": js["secrets"],
                      "sample_endpoints": js["endpoints"][:20]}
    except Exception as exc:
        js_summary = {"error": str(exc), "endpoints": 0, "secrets": [], "sample_endpoints": []}

    return {"domain": d, "subdomains_found": len(subs), "live_hosts": len(live),
            "targets": ranked, "apex_js": js_summary}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# playbook: {res['domain']}  "
             f"({res['subdomains_found']} subdomains, {res['live_hosts']} live)"]
    lines.append("## PRIORITIZED TARGETS (highest score first)")
    for t in res["targets"]:
        base = f"[{t['score']:>3}] {t['url']}  [{t['status']}]"
        if t["title"]:
            base += f'  "{t["title"]}"'
        lines.append(base)
        if t["reasons"]:
            lines.append("        " + " | ".join(t["reasons"]))
    js = res["apex_js"]
    lines.append(f"## apex JS: {js['endpoints']} endpoints, {len(js['secrets'])} secrets")
    if js["secrets"]:
        lines += [f"  [SECRET {s['type']}] {s['match']} (in {s['source']})" for s in js["secrets"]]
    if js["sample_endpoints"]:
        lines += [f"  {e}" for e in js["sample_endpoints"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.playbook",
        description="One-call recon: enumerate -> probe -> rank targets -> mine JS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python -m recon.playbook example.com\n")
    p.add_argument("domain", nargs="?", help="Apex domain to assess.")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.domain:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.domain, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
