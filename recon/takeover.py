"""Subdomain-takeover detection.

Chains the full recon flow in one call: enumerate subdomains (or take a supplied
list) -> resolve each name's CNAME/A -> flag records that dangle at a third-party
service whose resource looks unclaimed -> optionally confirm by fetching the
service's tell-tale error page. Returns only the interesting hosts, compactly,
so the operator isn't buried in the (usually large) full subdomain set.

A "takeover" is when a DNS record points at a provider (GitHub Pages, S3,
Heroku, ...) but the underlying resource is gone/unclaimed, so an attacker can
register it and serve content on your subdomain. Two independent signals are used:
  1. DANGLING DNS  — the CNAME target itself returns NXDOMAIN (nothing there).
  2. FINGERPRINT   — the HTTP response body matches the provider's "not found"
                     page for an unclaimed resource.

Confidence:
  high    = CNAME to a known service AND (dangling OR fingerprint matched), for a
            service that is reliably claimable.
  medium  = one signal present, or the service is claimable only in some setups.
  low     = CNAME points at a known service but it currently resolves & serves
            (informational: worth noting, not exploitable as-is).

Safety: passive recon. DNS is via DoH; the optional --confirm does a single plain
GET of each candidate host's root over HTTPS/HTTP to read the error page. It does
NOT attack, register, or claim anything. Read-only.

APIs: DoH (dns.google / cloudflare-dns.com) via common.dns; subdomain sources via
recon.subdomains. All free / no-auth.

Usage:
    python -m recon.takeover example.com                 # enum + check, DNS-only
    python -m recon.takeover example.com --confirm        # also fetch fingerprint pages
    python -m recon.takeover --hosts hosts.txt --json     # check a supplied list
    printf 'a.example.com\\nb.example.com\\n' | python -m recon.takeover --stdin
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys

from common import dns, http
from common.dns import NXDOMAIN
from common.output import emit, log

# --- fingerprint table ------------------------------------------------------
# Curated from the "can-i-take-over-xyz" project. Each entry:
#   service      human name
#   cnames       substrings that identify the provider in a CNAME target
#   fingerprint  text present on the provider's UNCLAIMED-resource page (or "")
#   vulnerable   True  -> reliably claimable
#                False -> edge/conditional; report but temper confidence
FINGERPRINTS: list[dict] = [
    {"service": "GitHub Pages", "cnames": ["github.io"],
     "fingerprint": "There isn't a GitHub Pages site here.", "vulnerable": True},
    {"service": "AWS/S3", "cnames": ["amazonaws.com", "s3.amazonaws"],
     "fingerprint": "The specified bucket does not exist", "vulnerable": True},
    {"service": "Heroku", "cnames": ["herokuapp.com", "herokussl", "herokudns.com"],
     "fingerprint": "No such app", "vulnerable": True},
    {"service": "Bitbucket", "cnames": ["bitbucket.io"],
     "fingerprint": "Repository not found", "vulnerable": True},
    {"service": "Surge.sh", "cnames": ["surge.sh"],
     "fingerprint": "project not found", "vulnerable": True},
    {"service": "Readme.io", "cnames": ["readme.io"],
     "fingerprint": "Project doesnt exist... yet!", "vulnerable": True},
    {"service": "Ghost", "cnames": ["ghost.io"],
     "fingerprint": "The thing you were looking for is no longer here", "vulnerable": True},
    {"service": "Webflow", "cnames": ["proxy-ssl.webflow.com", "webflow.io"],
     "fingerprint": "The page you are looking for doesn't exist or has been moved",
     "vulnerable": True},
    {"service": "Tumblr", "cnames": ["domains.tumblr.com"],
     "fingerprint": "Whatever you were looking for doesn't currently exist at this address",
     "vulnerable": True},
    {"service": "Wordpress", "cnames": ["wordpress.com"],
     "fingerprint": "Do you want to register", "vulnerable": False},
    {"service": "Cargo", "cnames": ["cargocollective.com"],
     "fingerprint": "404 Not Found", "vulnerable": False},
    {"service": "Pantheon", "cnames": ["pantheonsite.io"],
     "fingerprint": "The gods are wise, but do not know of the site which you seek",
     "vulnerable": True},
    {"service": "Tilda", "cnames": ["tilda.ws"],
     "fingerprint": "Please renew your subscription", "vulnerable": False},
    {"service": "Zendesk", "cnames": ["zendesk.com"],
     "fingerprint": "Help Center Closed", "vulnerable": False},
    {"service": "Shopify", "cnames": ["myshopify.com"],
     "fingerprint": "Sorry, this shop is currently unavailable", "vulnerable": False},
    {"service": "Fastly", "cnames": ["fastly.net"],
     "fingerprint": "Fastly error: unknown domain", "vulnerable": False},
    {"service": "Netlify", "cnames": ["netlify.app", "netlify.com"],
     "fingerprint": "Not Found - Request ID", "vulnerable": False},
    {"service": "Azure", "cnames": ["azurewebsites.net", "cloudapp.net",
     "trafficmanager.net", "azureedge.net", "cloudapp.azure.com"],
     "fingerprint": "404 Web Site not found", "vulnerable": True},
    {"service": "Unbounce", "cnames": ["unbouncepages.com"],
     "fingerprint": "The requested URL was not found on this server", "vulnerable": False},
    {"service": "Helpjuice", "cnames": ["helpjuice.com"],
     "fingerprint": "We could not find what you're looking for.", "vulnerable": True},
]


def _match_service(cname: str) -> dict | None:
    """Return the fingerprint entry whose provider owns ``cname``, or None."""
    low = cname.lower()
    for fp in FINGERPRINTS:
        if any(pat in low for pat in fp["cnames"]):
            return fp
    return None


def _fetch_body(host: str) -> str:
    """Single GET of the host root (https then http), returning body text or ''."""
    for scheme in ("https", "http"):
        r = http.get(f"{scheme}://{host}/", timeout=12, retries=0)
        if r.body:
            return r.text[:20000]  # cap: fingerprints appear early
    return ""


def check_host(host: str, *, confirm: bool = False) -> dict | None:
    """Check one host for takeover. Returns a finding dict if noteworthy, else None.

    Finding: {host, cname, service, confidence, dangling, fingerprint_matched,
              vulnerable_service, evidence}
    """
    rec = dns.resolve(host, "CNAME")
    cname = rec["cname"]
    if not cname:
        return None  # no CNAME -> not the classic takeover shape; skip quietly
    fp = _match_service(cname)
    if not fp:
        return None  # CNAME to something we don't have a fingerprint for

    # Signal 1: does the CNAME target itself dangle (NXDOMAIN)?
    target = dns.resolve(cname, "A")
    dangling = target["status"] == NXDOMAIN or (
        target["status"] == dns.NOERROR and not target["answers"]
    )

    # Signal 2: does the served page look unclaimed?
    fingerprint_matched = False
    evidence = ""
    if confirm and fp["fingerprint"]:
        body = _fetch_body(host)
        if fp["fingerprint"].lower() in body.lower():
            fingerprint_matched = True
            evidence = fp["fingerprint"]

    if dangling and fp["vulnerable"]:
        confidence = "high"
    elif fingerprint_matched and fp["vulnerable"]:
        confidence = "high"
    elif dangling or fingerprint_matched:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "host": host,
        "cname": cname,
        "service": fp["service"],
        "confidence": confidence,
        "dangling": dangling,
        "fingerprint_matched": fingerprint_matched,
        "vulnerable_service": fp["vulnerable"],
        "evidence": evidence,
    }


def run(domain: str | None = None, *, hosts: list[str] | None = None,
        confirm: bool = False) -> dict:
    """Enumerate (if given a domain) and check hosts for takeover.

    Args:
        domain: Apex to enumerate first (mutually usable with `hosts`).
        hosts: Explicit host list to check (skips enumeration if `domain` is None).
        confirm: Also fetch each candidate's page to match the fingerprint body.

    Returns:
        {"domain", "checked", "candidates":[finding,...], "summary":{by_confidence}}
    """
    targets: set[str] = set(hosts or [])
    if domain:
        from recon.subdomains import run as enum
        log(f"[*] enumerating {domain} ...")
        targets |= set(enum(domain)["subdomains"])
    targets = {t.strip().lower() for t in targets if t.strip()}

    log(f"[*] checking {len(targets)} hosts for takeover (confirm={confirm}) ...")
    findings: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futs = {pool.submit(check_host, h, confirm=confirm): h for h in targets}
        for fut in concurrent.futures.as_completed(futs):
            try:
                f = fut.result()
            except Exception:  # never let one host kill the sweep
                continue
            if f:
                findings.append(f)

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f["confidence"]], f["host"]))
    summary = {c: sum(1 for f in findings if f["confidence"] == c)
               for c in ("high", "medium", "low")}
    return {
        "domain": domain,
        "checked": len(targets),
        "candidates": findings,
        "summary": summary,
    }


def _compact_lines(res: dict) -> list[str]:
    s = res["summary"]
    head = (f"# takeover: checked {res['checked']} hosts  "
            f"high={s['high']} medium={s['medium']} low={s['low']}")
    lines = [head]
    if not res["candidates"]:
        lines.append("# no CNAMEs pointing at fingerprinted services found")
        return lines
    for f in res["candidates"]:
        flags = []
        if f["dangling"]:
            flags.append("DANGLING")
        if f["fingerprint_matched"]:
            flags.append("FP-MATCH")
        if not f["vulnerable_service"]:
            flags.append("edge-service")
        lines.append(
            f"[{f['confidence'].upper()}] {f['host']} -> {f['cname']} "
            f"({f['service']}) {' '.join(flags)}".rstrip()
        )
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.takeover",
        description="Detect subdomain takeovers: enum -> resolve CNAME -> fingerprint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m recon.takeover example.com --confirm\n"
            "  python -m recon.takeover --hosts hosts.txt --json\n"
            "  cat hosts.txt | python -m recon.takeover --stdin --confirm\n"
        ),
    )
    p.add_argument("domain", nargs="?", help="Apex domain to enumerate then check.")
    p.add_argument("--hosts", metavar="FILE", help="File with one host per line to check.")
    p.add_argument("--stdin", action="store_true", help="Read hosts (one per line) from stdin.")
    p.add_argument("--confirm", action="store_true",
                   help="Fetch each candidate's page to confirm the fingerprint (1 GET/host).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    hosts: list[str] = []
    if args.hosts:
        try:
            with open(args.hosts, encoding="utf-8") as fh:
                hosts += [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if args.stdin and not sys.stdin.isatty():
        hosts += [ln.strip() for ln in sys.stdin if ln.strip()]

    if not args.domain and not hosts:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.domain, hosts=hosts, confirm=args.confirm)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
