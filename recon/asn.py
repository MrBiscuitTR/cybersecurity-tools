"""Map an organization's network footprint: IP/domain/ASN -> ASN(s) -> netblocks.

Given an IP, a domain, or an ASN, this resolves the owning autonomous system and
lists every prefix it announces — turning one host into the whole routed address
space you might be in scope for. One call replaces a pile of whois/bgp lookups.

API: RIPEstat (RIPE NCC), free and no-auth. Privacy-respecting (chosen over
Google/BGP data brokers):
    https://stat.ripe.net/data/network-info/data.json      (IP -> ASN + prefix)
    https://stat.ripe.net/data/as-overview/data.json       (ASN -> holder name)
    https://stat.ripe.net/data/announced-prefixes/data.json (ASN -> all prefixes)

Safety: passive OSINT — only queries RIPEstat about public routing data. Touches
no target host. Read-only.

Usage:
    python -m recon.asn 1.1.1.1
    python -m recon.asn example.com --json
    python -m recon.asn AS13335 --max-prefixes 50
"""

from __future__ import annotations

import argparse
import sys

from common import dns, http
from common.output import emit, log

_RIPE = "https://stat.ripe.net/data"


def _ripe(endpoint: str, resource: str) -> dict:
    r = http.get(f"{_RIPE}/{endpoint}/data.json?resource={resource}", timeout=25, retries=1)
    if not r.ok:
        return {}
    try:
        return r.json().get("data", {})
    except ValueError:
        return {}


def _asns_for_ip(ip: str) -> tuple[list[str], str]:
    d = _ripe("network-info", ip)
    return [str(a) for a in d.get("asns", [])], d.get("prefix", "")


def _asn_detail(asn: str) -> dict:
    num = asn.upper().removeprefix("AS")
    overview = _ripe("as-overview", f"AS{num}")
    prefixes_data = _ripe("announced-prefixes", f"AS{num}")
    prefixes = [p["prefix"] for p in prefixes_data.get("prefixes", []) if "prefix" in p]
    v4 = [p for p in prefixes if ":" not in p]
    v6 = [p for p in prefixes if ":" in p]
    return {"asn": f"AS{num}", "holder": overview.get("holder", ""),
            "prefixes_v4": v4, "prefixes_v6": v6,
            "prefix_count": len(prefixes)}


def _classify(target: str) -> tuple[str, str]:
    """Return (kind, normalized). kind in {asn, ip, domain}."""
    import ipaddress
    t = target.strip()
    if t.upper().startswith("AS") and t[2:].isdigit():
        return "asn", t.upper()
    if t.isdigit():
        return "asn", "AS" + t
    try:
        return "ip", str(ipaddress.ip_address(t))
    except ValueError:
        return "domain", t.lower()


def run(target: str, *, max_prefixes: int = 500) -> dict:
    """Resolve ``target`` (IP/domain/ASN) to its ASN(s) and announced prefixes."""
    kind, norm = _classify(target)
    queried_ip, host_prefix = "", ""
    asns: list[str] = []

    if kind == "asn":
        asns = [norm]
    elif kind == "ip":
        queried_ip = norm
        asns, host_prefix = _asns_for_ip(norm)
    else:  # domain
        ips = dns.a_records(norm)
        if not ips:
            raise ValueError(f"could not resolve domain: {norm}")
        queried_ip = ips[0]
        log(f"[*] {norm} -> {queried_ip}")
        asns, host_prefix = _asns_for_ip(queried_ip)

    log(f"[*] ASNs: {asns or 'none'}")
    details = []
    for a in asns:
        d = _asn_detail(a)
        d["prefixes_v4"] = d["prefixes_v4"][:max_prefixes]
        d["prefixes_v6"] = d["prefixes_v6"][:max_prefixes]
        details.append(d)
    return {"target": target, "kind": kind, "queried_ip": queried_ip,
            "host_prefix": host_prefix, "asns": details}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# asn: {res['target']}"]
    if res["queried_ip"]:
        lines.append(f"# resolved IP: {res['queried_ip']}"
                     + (f"  (announced as {res['host_prefix']})" if res["host_prefix"] else ""))
    if not res["asns"]:
        lines.append("# no ASN found (unrouted / lookup failed)")
        return lines
    for a in res["asns"]:
        lines.append(f"## {a['asn']}  {a['holder']}  ({a['prefix_count']} prefixes)")
        shown = a["prefixes_v4"] + a["prefixes_v6"]
        lines += [f"  {p}" for p in shown]
        if a["prefix_count"] > len(shown):
            lines.append(f"  ... (+{a['prefix_count'] - len(shown)} more; use --json for all)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.asn",
        description="Map IP/domain/ASN to its autonomous system and announced netblocks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m recon.asn 1.1.1.1\n"
                "  python -m recon.asn example.com --json\n"
                "  python -m recon.asn AS13335 --max-prefixes 50\n"),
    )
    p.add_argument("target", nargs="?", help="An IP, a domain, or an ASN (AS13335 / 13335).")
    p.add_argument("--max-prefixes", type=int, default=500,
                   help="Cap prefixes shown per family (default 500; --json always has all).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.target, max_prefixes=args.max_prefixes)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
