"""Full DNS record dump for a domain, plus a zone-transfer (AXFR) attempt.

One call gives the operator the whole DNS picture: A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/SRV
records via privacy-first DoH, and — because a misconfigured nameserver handing out
its entire zone is a classic finding — an AXFR attempt against each authoritative
nameserver. Compact output, JSON available.

Why bundle AXFR here: enumerating record types and then trying a zone transfer is
the natural first-pass DNS recon flow; doing it in one shot saves the operator a
pile of dig invocations with fiddly flags.

APIs / network:
    - DoH resolvers (Quad9 -> Mullvad -> Cloudflare) via common.dns  (passive)
    - AXFR opens a direct TCP:53 socket to the domain's own nameservers. This is
      normal recon (you're asking the server to do something it should refuse),
      not an attack, and is read-only. Only the target's NS are contacted.

Safety: read-only. No records are modified. AXFR only reads whatever the server
is (mis)configured to give.

Usage:
    python -m recon.dns_records example.com
    python -m recon.dns_records example.com --json
    python -m recon.dns_records example.com --no-axfr        # skip zone transfer
"""

from __future__ import annotations

import argparse
import sys

from common import dns
from common.output import emit, log

# Record types worth pulling for a first-pass picture. SRV is a targeted lookup
# (needs a service prefix) so it's omitted from the blind sweep.
RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "CAA")


def run(domain: str, *, axfr: bool = True) -> dict:
    """Collect DNS records for ``domain`` and optionally attempt AXFR.

    Returns:
        {
          "domain": str,
          "records": {TYPE: [data, ...], ...},   # only non-empty types
          "nameservers": [str, ...],
          "axfr": [ {nameserver, ok, records|count, error}, ... ],  # [] if skipped
        }
    """
    from common.validate import domain as norm
    d = norm(domain)

    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        res = dns.resolve(d, rtype)
        vals = [a["data"] for a in res["answers"] if a["type"] == rtype]
        if vals:
            records[rtype] = sorted(set(vals))

    nameservers = records.get("NS", [])
    axfr_results: list[dict] = []
    if axfr and nameservers:
        for ns in nameservers:
            # Resolve NS name -> IP (AXFR needs an address to connect to).
            ns_ips = dns.a_records(ns) or [ns]
            for ip in ns_ips[:1]:  # one address per NS is enough
                log(f"[*] AXFR {d} @ {ns} ({ip}) ...")
                r = dns.axfr(d, ip)
                axfr_results.append({
                    "nameserver": ns,
                    "address": ip,
                    "ok": r["ok"],
                    "record_count": len(r["records"]),
                    "records": r["records"] if r["ok"] else [],
                    "error": r["error"],
                })

    return {
        "domain": d,
        "records": records,
        "nameservers": nameservers,
        "axfr": axfr_results,
    }


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# dns records: {res['domain']}"]
    for rtype in RECORD_TYPES:
        for val in res["records"].get(rtype, []):
            lines.append(f"{rtype:6} {val}")
    if res["axfr"]:
        any_ok = any(a["ok"] for a in res["axfr"])
        lines.append(f"## zone transfer (AXFR)  {'VULNERABLE' if any_ok else 'refused (good)'}")
        for a in res["axfr"]:
            if a["ok"]:
                lines.append(f"[OPEN] {a['nameserver']} -> {a['record_count']} records LEAKED")
                for rec in a["records"]:
                    lines.append(f"   {rec['type']:6} {rec['data']}")
            else:
                lines.append(f"[ok]   {a['nameserver']}: {a['error']}")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.dns_records",
        description="Dump all DNS records for a domain and attempt a zone transfer (AXFR).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m recon.dns_records example.com\n"
            "  python -m recon.dns_records example.com --json\n"
            "  python -m recon.dns_records example.com --no-axfr\n"
        ),
    )
    p.add_argument("domain", nargs="?", help="Domain to inspect (e.g. example.com).")
    p.add_argument("--no-axfr", action="store_true", help="Skip the zone-transfer attempt.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.domain:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.domain, axfr=not args.no_axfr)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
