"""Passive subdomain enumeration from many free, no-auth sources at once.

Why this exists: no single public source is complete or reliable. crt.sh is the
richest but is frequently 502/timeout. This tool queries 8 independent sources in
parallel, tolerates any of them failing, de-duplicates, and returns one compact
set — so the operator gets broad coverage in a single call without juggling flags.

Sources (all free, no API key required):
    crtsh        https://crt.sh/?q=%25.<d>&output=json          (CT logs; flaky)
    certspotter  https://api.certspotter.com/v1/issuances       (CT logs; reliable)
    hackertarget https://api.hackertarget.com/hostsearch/       (passive DNS; ~50/day free)
    wayback      http://web.archive.org/cdx/search/cdx          (archived URLs; slow, broad)
    urlscan      https://urlscan.io/api/v1/search/              (scan history)
    subdomaincenter https://api.subdomain.center/               (aggregated)
    rapiddns     https://rapiddns.io/subdomain/                 (passive DNS; HTML)
    otx          https://otx.alienvault.com/.../passive_dns     (rate-limited; backs off)

Auth/limits: none require a key. hackertarget and otx are rate-limited; a failure
of any one source is reported, not fatal.

Safety: fully passive. Only queries third-party APIs about the domain. With
``--resolve`` it additionally does DNS A lookups of discovered names (still
read-only, no traffic to the target's services). Never touches the target host.

Usage:
    python -m recon.subdomains example.com                # compact list to stdout
    python -m recon.subdomains example.com --json         # structured, complete
    python -m recon.subdomains example.com --resolve      # keep only names that resolve
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import sys
from typing import Callable
from urllib.parse import quote

from common import http
from common.output import emit, log
from common.validate import domain as norm_domain
from common.validate import is_subdomain_of

# --- individual source functions -------------------------------------------
# Each returns a set of hostnames (possibly noisy); the caller filters to the
# target domain and de-dups. Each must never raise: on failure return set().

_HOST_RE = re.compile(r"[A-Za-z0-9_.-]+")


def _src_crtsh(d: str) -> set[str]:
    r = http.get(f"https://crt.sh/?q=%25.{quote(d)}&output=json", timeout=25)
    if not r.ok:
        return set()
    try:
        rows = r.json()
    except ValueError:
        return set()
    out: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            out.add(name)
    return out


def _src_certspotter(d: str) -> set[str]:
    url = (
        f"https://api.certspotter.com/v1/issuances?domain={quote(d)}"
        "&include_subdomains=true&expand=dns_names"
    )
    r = http.get(url, timeout=20)
    if not r.ok:
        return set()
    try:
        rows = r.json()
    except ValueError:
        return set()
    return {n for row in rows for n in row.get("dns_names", [])}


def _src_hackertarget(d: str) -> set[str]:
    r = http.get(f"https://api.hackertarget.com/hostsearch/?q={quote(d)}", timeout=20)
    if not r.ok or b"error" in r.body[:40].lower() or b"API count" in r.body:
        return set()
    return {line.split(",", 1)[0] for line in r.text.splitlines() if "," in line}


def _src_wayback(d: str) -> set[str]:
    url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{quote(d)}"
        "&output=json&fl=original&collapse=urlkey&limit=20000"
    )
    r = http.get(url, timeout=30)
    if not r.ok:
        return set()
    try:
        rows = r.json()
    except ValueError:
        return set()
    out: set[str] = set()
    for row in rows[1:]:  # first row is the header
        m = re.search(r"https?://([^/:]+)", row[0])
        if m:
            out.add(m.group(1))
    return out


def _src_urlscan(d: str) -> set[str]:
    r = http.get(f"https://urlscan.io/api/v1/search/?q=domain:{quote(d)}&size=1000", timeout=25)
    if not r.ok:
        return set()
    try:
        data = r.json()
    except ValueError:
        return set()
    out: set[str] = set()
    for res in data.get("results", []):
        page = res.get("page", {})
        if page.get("domain"):
            out.add(page["domain"])
        for name in _HOST_RE.findall(str(res.get("task", {}).get("url", ""))):
            out.add(name)
    return out


def _src_subdomaincenter(d: str) -> set[str]:
    r = http.get(f"https://api.subdomain.center/?domain={quote(d)}", timeout=20)
    if not r.ok:
        return set()
    try:
        data = r.json()
    except ValueError:
        return set()
    return set(data) if isinstance(data, list) else set()


def _src_rapiddns(d: str) -> set[str]:
    r = http.get(f"https://rapiddns.io/subdomain/{quote(d)}?full=1", timeout=25)
    if not r.ok:
        return set()
    # Scrape hostnames out of the HTML table cells.
    return set(re.findall(rf"[A-Za-z0-9_.-]+\.{re.escape(d)}", r.text))


def _src_otx(d: str) -> set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(d)}/passive_dns"
    r = http.get(url, timeout=20)
    if not r.ok:
        return set()
    try:
        data = r.json()
    except ValueError:
        return set()
    return {e.get("hostname", "") for e in data.get("passive_dns", [])}


SOURCES: dict[str, Callable[[str], set[str]]] = {
    "crtsh": _src_crtsh,
    "certspotter": _src_certspotter,
    "hackertarget": _src_hackertarget,
    "wayback": _src_wayback,
    "urlscan": _src_urlscan,
    "subdomaincenter": _src_subdomaincenter,
    "rapiddns": _src_rapiddns,
    "otx": _src_otx,
}


def _resolve(host: str) -> str | None:
    """Return one A-record IP for ``host`` or None if it doesn't resolve."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        return None


def run(target: str, *, resolve: bool = False, sources: list[str] | None = None) -> dict:
    """Enumerate subdomains of ``target`` across all sources.

    Args:
        target: The apex/registrable domain (or any form validate.domain accepts).
        resolve: If True, DNS-resolve each candidate and keep only live ones,
            recording their IPs.
        sources: Restrict to these source names (default: all).

    Returns:
        {
          "domain": str,
          "count": int,
          "subdomains": [str, ...] | [{"host":str,"ip":str}, ...],  # sorted
          "sources": {name: n_found_or_"err", ...},
          "errors": {name: "reason", ...},
        }
    """
    d = norm_domain(target)
    chosen = {k: SOURCES[k] for k in (sources or SOURCES) if k in SOURCES}

    found: set[str] = set()
    per_source: dict[str, object] = {}
    errors: dict[str, str] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(chosen)) as pool:
        futs = {pool.submit(fn, d): name for name, fn in chosen.items()}
        for fut in concurrent.futures.as_completed(futs):
            name = futs[fut]
            try:
                hits = {h.strip(".").lower() for h in fut.result() if h}
            except Exception as exc:  # a source should never kill the run
                per_source[name], errors[name] = "err", f"{type(exc).__name__}: {exc}"
                continue
            hits = {h for h in hits if is_subdomain_of(h, d)}
            per_source[name] = len(hits)
            if not hits:
                errors.setdefault(name, "no results / unavailable")
            found |= hits

    names = sorted(found)
    if resolve:
        live: list[dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            for host, ipaddr in zip(names, pool.map(_resolve, names)):
                if ipaddr:
                    live.append({"host": host, "ip": ipaddr})
        result_subs: list = live
        count = len(live)
    else:
        result_subs = names
        count = len(names)

    return {
        "domain": d,
        "count": count,
        "subdomains": result_subs,
        "sources": per_source,
        "errors": errors,
    }


def _compact_lines(res: dict, resolved: bool) -> list[str]:
    """Render the smallest useful human view."""
    ok = {k: v for k, v in res["sources"].items() if isinstance(v, int) and v > 0}
    hdr = (
        f"# {res['domain']}  {res['count']} subdomains  "
        f"({len(ok)}/{len(res['sources'])} sources hit)"
    )
    src = "# sources: " + ", ".join(f"{k}={v}" for k, v in sorted(res["sources"].items()))
    lines = [hdr, src]
    if res["errors"]:
        lines.append("# down: " + ", ".join(sorted(res["errors"])))
    if resolved:
        lines += [f"{r['host']} {r['ip']}" for r in res["subdomains"]]
    else:
        lines += list(res["subdomains"])
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.subdomains",
        description="Passive subdomain enumeration from 8 free no-auth sources, de-duplicated.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m recon.subdomains example.com\n"
            "  python -m recon.subdomains example.com --resolve --json\n"
            "  python -m recon.subdomains example.com --sources crtsh,certspotter\n"
        ),
    )
    p.add_argument("domain", nargs="?", help="Apex domain to enumerate (e.g. example.com).")
    p.add_argument("--resolve", action="store_true",
                   help="DNS-resolve results and keep only live names (adds IPs).")
    p.add_argument("--sources", metavar="A,B",
                   help="Comma-separated subset of: " + ",".join(SOURCES))
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.domain:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        target = args.domain
        srcs = [s.strip() for s in args.sources.split(",")] if args.sources else None
        log(f"[*] querying {len(srcs or SOURCES)} sources for {target} ...")
        res = run(target, resolve=args.resolve, sources=srcs)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res, args.resolve))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
