"""MCP server exposing the repo's tools to an LLM operator.

Run it (stdio transport, the usual for local MCP clients):

    pip install mcp        # one-time
    python -m mcp_server.server

Or register it with an MCP-capable client pointing at the same command.

Each tool below wraps a plain ``run()`` from the library and returns COMPACT
text tuned for a limited context window. The long, teaching-style descriptions
come from :mod:`mcp_server.guides` so a smaller model gets the intuition it may
lack: how to read the output, what to do next, and when to retry.

Nothing here is destructive; every tool is read-only / passive as documented.
"""

from __future__ import annotations

import sys

from forensics import pcap as _pcap
from malware import triage as _triage
from mcp_server import guides
from recon import dns_records as _dns_records
from recon import http_probe as _http_probe
from recon import subdomains as _subdomains
from recon import takeover as _takeover
from web import tls_audit as _tls_audit


def _require_mcp():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:  # pragma: no cover - env without the SDK
        sys.stderr.write(
            "The 'mcp' package is not installed. Run: pip install mcp\n"
            "(The tools themselves work standalone via `python -m <category>.<tool>`.)\n"
        )
        raise SystemExit(1)
    return FastMCP


def build_app():
    """Construct and return the FastMCP app with all tools registered."""
    FastMCP = _require_mcp()
    app = FastMCP("cybersecurity-tools")

    @app.tool(description=guides.SUBDOMAINS)
    def enum_subdomains(domain: str, resolve: bool = False) -> str:
        """Enumerate subdomains of `domain`. See the tool description for output
        format and interpretation. Returns compact text (one host per line)."""
        res = _subdomains.run(domain, resolve=resolve)
        return "\n".join(_subdomains._compact_lines(res, resolve))

    @app.tool(description=guides.TAKEOVER)
    def check_takeover(domain: str = "", hosts: list[str] | None = None,
                       confirm: bool = False) -> str:
        """Detect subdomain takeovers. Pass a `domain` to enumerate+check, or a
        `hosts` list. See the tool description for confidence levels (esp. LOW =
        not exploitable). Returns compact text, most-severe first."""
        res = _takeover.run(domain or None, hosts=hosts or None, confirm=confirm)
        return "\n".join(_takeover._compact_lines(res))

    @app.tool(description=guides.HTTP_PROBE)
    def http_probe(target: str = "", hosts: list[str] | None = None,
                   enum: bool = False, show_dead: bool = False) -> str:
        """Probe hosts over HTTP(S); one line per live host. Set enum=true to
        enumerate a domain's subdomains first. See the tool description for how to
        read the output and prioritize. Returns compact text."""
        targets = list(hosts or [])
        if target:
            if enum:
                targets += _subdomains.run(target)["subdomains"] + [target]
            else:
                targets.append(target)
        if not targets:
            return "no targets provided"
        res = _http_probe.run(targets)
        return "\n".join(_http_probe._compact_lines(res, show_dead))

    @app.tool(description=guides.DNS_RECORDS)
    def dns_records(domain: str, axfr: bool = True) -> str:
        """Dump all DNS records for a domain and attempt a zone transfer. See the
        tool description for reading the AXFR result. Returns compact text."""
        res = _dns_records.run(domain, axfr=axfr)
        return "\n".join(_dns_records._compact_lines(res))

    @app.tool(description=guides.TLS_AUDIT)
    def tls_audit(target: str, version_probe: bool = True) -> str:
        """Audit TLS config + HTTP security headers for host[:port]. See the tool
        description for the FINDINGS ranking. Returns compact text."""
        res = _tls_audit.run(target, version_probe=version_probe)
        return "\n".join(_tls_audit._compact_lines(res))

    @app.tool(description=guides.TRIAGE)
    def triage_file(file: str, min_str: int = 4, max_strings: int = 200) -> str:
        """Static triage of a file: hashes, entropy, strings/IOCs, PE/ELF internals,
        ranked red flags. Never executes it. See the tool description for how to
        read the flags. Returns compact text."""
        res = _triage.run(file, min_str=min_str, max_strings=max_strings)
        return "\n".join(_triage._compact_lines(res))

    @app.tool(description=guides.PCAP)
    def analyze_pcap(file: str, sections: str = "", stream: str = "",
                     dfilter: str = "", tshark: str = "") -> str:
        """Analyze a capture. Default: digest. Set `stream` (e.g. "5" or "udp:3")
        to follow a reassembled stream, or `dfilter` to run a Wireshark display
        filter. See the tool description for all sections/modes. Compact text."""
        ts = tshark or None
        if stream:
            data = _pcap.follow(file, stream, tshark=ts)
            return f"# follow {data['proto']} stream {data['stream']}\n{data['content']}"
        if dfilter:
            data = _pcap.filter_packets(file, dfilter, tshark=ts)
            head = f"# filter: {data['filter']}  matched {data['matched']}"
            return "\n".join([head] + data["packets"])
        secs = [s.strip() for s in sections.split(",")] if sections else None
        res = _pcap.run(file, sections=secs, tshark=ts)
        return "\n".join(_pcap._compact_lines(res))

    return app


def main() -> int:
    app = build_app()
    app.run()  # stdio transport
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
