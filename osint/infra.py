"""Infrastructure entities for a domain: DNS, IPs, netblocks, ASN, WHOIS, tech.

The bridge between person-centric OSINT and the network side of the repo. Once a
subject's personal site or an employer's mail domain turns up, the domain itself
becomes an entity with its own graph — registrar and registration dates, mail
provider, name servers, the IPs it resolves to, the netblock and autonomous
system that owns those IPs, the TLS certificate (which names further domains and
often the legal organization), the web stack, and the subdomains.

This wraps the recon/web tools already in the repo rather than reimplementing
them, and adds RDAP registration data, which is the piece person-OSINT actually
wants: registrar, creation date, and — when not redacted — registrant
organization and country.

Modules reused:
    recon.dns_records   A/AAAA/NS/MX/TXT/SOA/CNAME/CAA over privacy-first DoH
    recon.asn           IP/domain -> ASN + every announced prefix (RIPEstat)
    recon.subdomains    8 passive sources, de-duplicated
    recon.http_probe    liveness, title, server banner, technology guess
    web.tls_audit       certificate subject/issuer/SANs and TLS posture

External APIs: RDAP via rdap.org (free, no auth) with the IANA bootstrap as a
fallback, plus whatever the reused modules call.

Safety: passive by default — DNS, RDAP and third-party APIs only. ``--active``
additionally makes ordinary HTTP(S) and TLS connections to the host itself, the
same requests a browser makes. Nothing is written and nothing is fuzzed. Only
run --active against infrastructure you are authorized to touch.

Usage:
    python -m osint.infra example.com
    python -m osint.infra example.com --active --json
    python -m osint.infra example.com --subdomains
"""

from __future__ import annotations

import argparse
import sys

from common.output import emit, log
from common.validate import domain as norm_domain
from osint import fetch


def rdap(domain: str, *, timeout: float = 20.0) -> dict:
    """Fetch RDAP registration data for a domain.

    Tries rdap.org (which redirects to the authoritative registry) and falls back
    to the IANA bootstrap service. Registrant contact details are redacted for
    most TLDs post-GDPR; registrar, creation/expiry dates and status codes are
    not, and those are the useful part.

    Args:
        domain: Registrable domain.
        timeout: Request timeout.

    Returns:
        ``{"registrar","created","updated","expires","status","nameservers",
        "registrant_org","registrant_country","source"}`` or ``{}``.
    """
    for base in (f"https://rdap.org/domain/{domain}",
                 f"https://rdap.iana.org/domain/{domain}"):
        data, resp = fetch.get_json(base, timeout=timeout)
        if not isinstance(data, dict) or "objectClassName" not in data:
            continue
        events = {e.get("eventAction", ""): e.get("eventDate", "")
                  for e in data.get("events", []) if isinstance(e, dict)}
        registrar, org, country = "", "", ""
        for ent in data.get("entities", []) or []:
            roles = [r.lower() for r in ent.get("roles", [])]
            vcard = ent.get("vcardArray") or []
            fields = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
            values = {f[0]: f[3] for f in fields
                      if isinstance(f, list) and len(f) > 3 and isinstance(f[0], str)}
            if "registrar" in roles and not registrar:
                registrar = str(values.get("fn", "") or ent.get("handle", ""))
            if "registrant" in roles:
                org = org or str(values.get("org", "") or values.get("fn", ""))
                adr = values.get("adr")
                if isinstance(adr, list) and adr:
                    country = country or str(adr[-1] or "")
        return {
            "registrar": registrar,
            "created": events.get("registration", ""),
            "updated": events.get("last changed", events.get("last update of RDAP database", "")),
            "expires": events.get("expiration", ""),
            "status": data.get("status", []),
            "nameservers": sorted({str(ns.get("ldhName", "")).lower()
                                   for ns in data.get("nameservers", []) or []
                                   if ns.get("ldhName")}),
            "registrant_org": org,
            "registrant_country": country,
            "source": resp.final_url if resp else base,
        }
    return {}


def run(
    domain: str,
    *,
    active: bool = False,
    subdomains: bool = False,
    timeout: float = 20.0,
) -> dict:
    """Build the infrastructure picture for one domain.

    Args:
        domain: Domain (a URL or an email address' domain part is fine).
        active: Also connect to the host itself for HTTP(S) and TLS data.
        subdomains: Also run passive subdomain enumeration (slower, 8 sources).
        timeout: Per-request timeout.

    Returns:
        ``{"domain","rdap","dns","ips","asn","tls","http","subdomains",
        "related_domains","sources_up","sources_down","next_steps"}``.

    Raises:
        ValueError: If ``domain`` isn't a plausible domain.
    """
    d = norm_domain(domain)
    log(f"[*] infra: {d} (active={active}, subdomains={subdomains})")

    from recon import asn as asn_mod
    from recon import dns_records

    sources: dict[str, object] = {
        "rdap": lambda: rdap(d, timeout=timeout),
        "dns": lambda: dns_records.run(d, axfr=False),
        "asn": lambda: asn_mod.run(d),
    }
    if subdomains:
        from recon import subdomains as subs_mod
        # resolve=True keeps only live names AND returns their IPs, which is
        # the point: every distinct address in the person's footprint.
        sources["subdomains"] = lambda: subs_mod.run(d, resolve=True)
    if active:
        from recon import http_probe
        from web import tls_audit
        sources["http"] = lambda: http_probe.run([d], timeout=timeout)
        sources["tls"] = lambda: tls_audit.run(d, timeout=timeout)

    got, down = fetch.gather(sources, workers=5, timeout=timeout * 5)  # type: ignore[arg-type]

    dns_data = got.get("dns", {}) or {}
    records = dns_data.get("records", {}) or {}
    ips = sorted(set(records.get("A", []) + records.get("AAAA", [])))

    asn_data = got.get("asn", {}) or {}
    asns = [{"asn": a.get("asn", ""), "holder": a.get("holder", ""),
             "prefix_count": a.get("prefix_count", 0),
             "prefixes": (a.get("prefixes_v4", []) + a.get("prefixes_v6", []))[:20]}
            for a in asn_data.get("asns", [])]

    tls = got.get("tls", {}) or {}
    cert = tls.get("cert", {}) or {}
    http_res = ((got.get("http", {}) or {}).get("results") or [{}])[0]

    # Certificate SANs and MX hosts name further domains worth investigating.
    related: set[str] = set()
    for san in cert.get("sans", []) or []:
        san = str(san).lstrip("*.").lower()
        if san and san != d:
            related.add(san)
    for mx in records.get("MX", []):
        host = str(mx).split()[-1].rstrip(".").lower()
        if host and not host.endswith(d):
            related.add(host)

    cert_org = cert.get("organization", "") or cert.get("subject_org", "")

    steps = []
    r = got.get("rdap", {}) or {}
    if r.get("registrant_org"):
        steps.append(f"RDAP names registrant org '{r['registrant_org']}' — run "
                     "osint.records on it for corporate registration data.")
    elif r.get("registrar"):
        steps.append("Registrant details are redacted (normal post-GDPR); the "
                     "registrar and creation date are still usable as pivots.")
    if cert_org:
        steps.append(f"TLS certificate names organization '{cert_org}' — that is a "
                     "legal entity, feed it to osint.records.")
    if related:
        steps.append(f"{len(related)} related domains from cert SANs / MX — each is "
                     "another osint.infra target.")
    if records.get("MX"):
        provider = ", ".join(sorted({str(m).split()[-1].split('.')[-2:][0]
                                     for m in records["MX"] if str(m).split()})) or "?"
        steps.append(f"Mail is handled by {provider} — that tells you where any "
                     "corporate address at this domain actually lands.")
    if not active:
        steps.append("Run with --active for HTTP fingerprinting and the TLS "
                     "certificate (only against hosts you're authorized to touch).")

    # With resolve=True, recon.subdomains returns [{"host","ip"}, ...] — only
    # names that actually resolve, each with the address it points at.
    subs_data = got.get("subdomains", {}) or {}
    raw_subs = subs_data.get("subdomains", []) or []
    sub_names = sorted({s["host"] if isinstance(s, dict) else str(s)
                        for s in raw_subs})
    sub_ips = sorted({s["ip"] for s in raw_subs
                      if isinstance(s, dict) and s.get("ip")})

    return {"domain": d, "rdap": r, "dns": records,
            "subdomain_ips": sub_ips,
            "nameservers": records.get("NS", []), "mx": records.get("MX", []),
            "ips": ips, "asn": asns,
            "tls": {"subject": cert.get("subject", ""),
                    "organization": cert_org,
                    "issuer": cert.get("issuer", ""),
                    "not_after": cert.get("not_after", ""),
                    "self_signed": cert.get("self_signed", False),
                    "sans": cert.get("sans", [])[:30]} if tls else {},
            "http": {"status": http_res.get("status"), "title": http_res.get("title", ""),
                     "server": http_res.get("server", ""),
                     "tech": http_res.get("tech", [])} if http_res else {},
            "subdomains": sub_names,
            "related_domains": sorted(related),
            "sources_up": sorted(got), "sources_down": down, "next_steps": steps}


def _compact_lines(res: dict) -> list[str]:
    empty, failed = fetch.split_down(res["sources_down"])
    lines = [f"# infra: {res['domain']}",
             f"# sources with data: {', '.join(res['sources_up']) or 'none'}"]
    if empty:
        lines.append(f"# no data from: {', '.join(empty)}")
    if failed:
        lines.append(f"# unavailable: {', '.join(failed)}")

    r = res["rdap"]
    if r:
        lines.append("## REGISTRATION (RDAP)")
        for k in ("registrar", "created", "updated", "expires",
                  "registrant_org", "registrant_country"):
            if r.get(k):
                lines.append(f"  {k:<20} {r[k]}")
        if r.get("status"):
            lines.append(f"  {'status':<20} {', '.join(r['status'])}")

    if res["ips"]:
        lines.append(f"## IP ADDRESSES ({len(res['ips'])})")
        lines.append("  " + ", ".join(res["ips"]))
    for a in res["asn"]:
        lines.append(f"## {a['asn']}  {a['holder']}  ({a['prefix_count']} prefixes)")
        if a["prefixes"]:
            lines.append("  netblocks: " + ", ".join(a["prefixes"][:10]))
    if res["nameservers"]:
        lines.append(f"## NAME SERVERS\n  {', '.join(res['nameservers'])}")
    if res["mx"]:
        lines.append(f"## MAIL (MX)\n  {', '.join(res['mx'])}")

    tls = res["tls"]
    if tls and any(tls.values()):
        lines.append("## TLS CERTIFICATE")
        for k in ("subject", "organization", "issuer", "not_after"):
            if tls.get(k):
                lines.append(f"  {k:<20} {tls[k]}")
        if tls.get("sans"):
            lines.append(f"  {'sans':<20} {', '.join(tls['sans'][:12])}")
    http = res["http"]
    if http and http.get("status"):
        lines.append(f"## WEB  [{http['status']}] {http.get('title', '')[:80]}")
        if http.get("server"):
            lines.append(f"  server: {http['server']}")
        if http.get("tech"):
            lines.append(f"  tech:   {', '.join(http['tech'])}")
    if res["related_domains"]:
        lines.append(f"## RELATED DOMAINS ({len(res['related_domains'])})")
        lines.append("  " + ", ".join(res["related_domains"][:30]))
    if res["subdomains"]:
        lines.append(f"## SUBDOMAINS ({len(res['subdomains'])}, live)")
        lines.append("  " + ", ".join(res["subdomains"]))
    if res.get("subdomain_ips"):
        lines.append(f"## SUBDOMAIN IPs ({len(res['subdomain_ips'])})")
        lines.append("  " + ", ".join(res["subdomain_ips"]))
    lines.append("## NEXT")
    lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.infra",
        description="Domain infrastructure: RDAP, DNS, IPs, netblocks, ASN, TLS, tech.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m osint.infra example.com\n"
                "  python -m osint.infra example.com --active --json\n"
                "  python -m osint.infra example.com --subdomains\n"
                "\nPassive by default. --active connects to the host itself;\n"
                "only use it on infrastructure you are authorized to touch.\n"),
    )
    p.add_argument("domain", nargs="?", help="Domain to profile.")
    p.add_argument("--active", action="store_true",
                   help="Also fetch HTTP(S) and the TLS certificate from the host.")
    p.add_argument("--subdomains", action="store_true",
                   help="Also run passive subdomain enumeration (8 sources).")
    p.add_argument("--timeout", type=float, default=20.0, help="Timeout (default 20).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.domain:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(args.domain, active=args.active, subdomains=args.subdomains,
                  timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
