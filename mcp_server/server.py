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

from analyze import bughunt as _bughunt
from analyze import exploit_advisor as _exploit_advisor
from crypto import oracle as _oracle
from cloud import iam_enum as _iam_enum
from common import notes as _notes
from common import safe_bash as _safe_bash
from cloud import s3_hunt as _s3_hunt
from forensics import log_triage as _log_triage
from forensics import pcap as _pcap
from malware import yara_gen as _yara_gen
from malware import triage as _triage
from mcp_server import guides
from reversing import bindiff as _bindiff
from reversing import decompile as _decompile
from reversing import disasm as _disasm
from reversing import firmware as _firmware
from reversing import gadgets as _gadgets
from reversing import pwn_template as _pwn_template
from reversing import symbolic as _symbolic
from recon import asn as _asn
from recon import dns_records as _dns_records
from recon import favicon as _favicon
from recon import http_probe as _http_probe
from recon import nuclei as _nuclei
from recon import playbook as _playbook
from recon import secrets_scan as _secrets_scan
from recon import subdomains as _subdomains
from recon import takeover as _takeover
from web import cors as _cors
from web import dirfuzz as _dirfuzz
from web import graphql as _graphql
from web import js_recon as _js_recon
from web import jwt_audit as _jwt
from web import oauth as _oauth
from web import smuggle as _smuggle
from web import ssrf as _ssrf
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

    @app.tool(description=guides.JWT)
    def jwt(action: str = "decode", token: str = "", secret: str = "",
            key_pem: str = "", public_key_pem: str = "", alg: str = "",
            payload: str = "", header: str = "{}", wordlist: str = "") -> str:
        """Decode/verify/sign/crack/attack a JWT. Set `action` and pass only that
        action's fields (see the tool description). Returns compact text."""
        import json as _json
        if action == "decode":
            return "\n".join(_jwt._decode_lines(_jwt.analyze(token)))
        if action == "verify":
            r = _jwt.verify(token, secret or key_pem)
            return f"verify: {'VALID' if r['valid'] else 'INVALID'}  alg={r['alg']}  ({r['reason']})"
        if action == "sign":
            return _jwt.sign(_json.loads(header or "{}"), _json.loads(payload),
                             secret or key_pem, alg)
        if action == "crack":
            with open(wordlist, encoding="utf-8", errors="ignore") as fh:
                s = _jwt.crack_hs(token, fh)
            return f"crack: {'FOUND secret=' + s if s else 'not found'}"
        if action == "attack":
            words = open(wordlist, encoding="utf-8", errors="ignore") if wordlist else None
            res = _jwt.attack(token, public_key=public_key_pem or None, words=words)
            if words:
                words.close()
            out = []
            for a in res["attacks"]:
                tag = a.get("variant") or a.get("secret") or ""
                out += [f"## {a['attack']} {tag}".rstrip(), a["token"], f"   note: {a['note']}"]
            return "\n".join(out)
        return f"unknown action {action!r}; use decode|verify|sign|crack|attack"

    @app.tool(description=guides.JS_RECON)
    def js_recon(target: str, only_secrets: bool = False) -> str:
        """Mine a site's JavaScript for endpoints, secrets, and params. See the
        tool description for how to read/verify secrets. Returns compact text."""
        res = _js_recon.run(target)
        return "\n".join(_js_recon._compact_lines(res, only_secrets))

    @app.tool(description=guides.NUCLEI)
    def nuclei(target: str, severity: str = "", tags: str = "") -> str:
        """Run nuclei and return ranked, de-duplicated findings. See the tool
        description. Returns compact text."""
        return "\n".join(_nuclei._compact_lines(_nuclei.run(target, severity=severity, tags=tags)))

    @app.tool(description=guides.DIRFUZZ)
    def dirfuzz(base: str, wordlist: str = "", ext: str = "") -> str:
        """Content discovery with soft-404 filtering. See the tool description.
        Returns compact text."""
        exts = [e.strip() for e in ext.split(",") if e.strip()] if ext else []
        return "\n".join(_dirfuzz._compact_lines(_dirfuzz.run(base, wordlist=wordlist, exts=exts)))

    @app.tool(description=guides.SSRF)
    def ssrf(url: str, param: str = "", callback: str = "") -> str:
        """Probe a parameter for SSRF (mark with FUZZ or use param). See the tool
        description. Returns compact text."""
        return "\n".join(_ssrf._compact_lines(_ssrf.run(url, param=param, callback=callback)))

    @app.tool(description=guides.SMUGGLE)
    def smuggle(url: str, rounds: int = 2) -> str:
        """Detect HTTP request smuggling (CL.TE/TE.CL) by timing. See the tool
        description. Returns compact text."""
        return "\n".join(_smuggle._compact_lines(_smuggle.run(url, rounds=rounds)))

    @app.tool(description=guides.ORACLE)
    def crypto_oracle(mode: str, data: str, oracle: str = "", encoding: str = "hex",
                      invalid: str = "", valid_status: int = 0) -> str:
        """ECB detection / CBC padding-oracle decryption. mode=ecb-detect|padding.
        See the tool description. Returns compact text."""
        res = _oracle.run(mode, data=data, oracle_url=oracle, encoding=encoding,
                          invalid=invalid, valid_status=valid_status or None)
        return "\n".join(_oracle._compact_lines(res))

    @app.tool(description=guides.GRAPHQL)
    def graphql(url: str) -> str:
        """Introspect + audit a GraphQL endpoint. See the tool description. Compact text."""
        return "\n".join(_graphql._compact_lines(_graphql.run(url)))

    @app.tool(description=guides.CORS)
    def cors(url: str) -> str:
        """Test a URL for CORS misconfigurations. See the tool description. Compact text."""
        return "\n".join(_cors._compact_lines(_cors.run(url)))

    @app.tool(description=guides.OAUTH)
    def oauth(target: str) -> str:
        """Map an OAuth/OIDC deployment and flag weaknesses. See the tool description. Compact text."""
        return "\n".join(_oauth._compact_lines(_oauth.run(target)))

    @app.tool(description=guides.S3_HUNT)
    def s3_hunt(keyword: str = "", bucket: str = "") -> str:
        """Hunt public S3/GCS/Azure buckets from a keyword (or check one `bucket`).
        See the tool description. Returns compact text."""
        return "\n".join(_s3_hunt._compact_lines(_s3_hunt.run(keyword, bucket=bucket)))

    @app.tool(description=guides.IAM_ENUM)
    def iam_enum(profile: str = "", region: str = "us-east-1") -> str:
        """Enumerate an AWS identity's read-only permissions (needs AWS creds in env
        or `profile`). See the tool description. Returns compact text."""
        return "\n".join(_iam_enum._compact_lines(_iam_enum.run(profile=profile, region=region)))

    @app.tool(description=guides.YARA_GEN)
    def yara_gen(file: str, name: str = "") -> str:
        """Generate a YARA rule from a sample for threat hunting. See the tool
        description. Returns compact text (the rule)."""
        return "\n".join(_yara_gen._compact_lines(_yara_gen.run(file, name=name)))

    @app.tool(description=guides.SAFE_BASH)
    def bash(command: str, cwd: str = "", timeout: float = 60.0) -> str:
        """Run a shell command through the host-safety policy (destructive commands are
        blocked, never executed). See the tool description for what's allowed. Compact text."""
        res = _safe_bash.run(command, cwd=cwd or None, timeout=timeout)
        return "\n".join(_safe_bash._compact_lines(res))

    @app.tool(description=guides.NOTES)
    def notes(action: str = "read", content: str = "", file: str = _notes.DEFAULT_FILE) -> str:
        """Persistent scratch notes (append/read/clear) that survive compaction. See the
        tool description — take notes constantly. Returns compact text."""
        return "\n".join(_notes._compact_lines(_notes.run(action, content=content, file=file)))

    @app.tool(description=guides.BUGHUNT)
    def bughunt(target: str, classes: str = "") -> str:
        """Sweep a repo (URL or path) for vulnerability patterns; writes a notes file.
        ONLY when the user asks to hunt bugs. See the tool description for the hacker
        methodology to turn leads into confirmed bugs. Returns compact text."""
        cl = [c.strip() for c in classes.split(",")] if classes else None
        return "\n".join(_bughunt._compact_lines(_bughunt.run(target, classes=cl)))

    @app.tool(description=guides.EXPLOIT_ADVISOR)
    def exploit_advisor(file: str) -> str:
        """Static triage -> prioritized exploitation action plan for a binary. See
        the tool description. Returns compact text."""
        return "\n".join(_exploit_advisor._compact_lines(_exploit_advisor.run(file)))

    @app.tool(description=guides.PLAYBOOK)
    def playbook(domain: str) -> str:
        """One-call recon: enumerate -> probe -> rank targets -> mine JS. See the
        tool description. Returns a prioritized target list as compact text."""
        return "\n".join(_playbook._compact_lines(_playbook.run(domain)))

    @app.tool(description=guides.TLS_AUDIT)
    def tls_audit(target: str, version_probe: bool = True) -> str:
        """Audit TLS config + HTTP security headers for host[:port]. See the tool
        description for the FINDINGS ranking. Returns compact text."""
        res = _tls_audit.run(target, version_probe=version_probe)
        return "\n".join(_tls_audit._compact_lines(res))

    @app.tool(description=guides.ASN)
    def asn(target: str, max_prefixes: int = 500) -> str:
        """Map an IP/domain/ASN to its autonomous system and announced netblocks.
        See the tool description (mind scope on shared cloud ASNs). Compact text."""
        return "\n".join(_asn._compact_lines(_asn.run(target, max_prefixes=max_prefixes)))

    @app.tool(description=guides.FAVICON)
    def favicon(target: str) -> str:
        """Compute a site's favicon hash + Shodan/FOFA/ZoomEye pivots to find hosts
        sharing it (e.g. a CDN-hidden origin). Returns compact text."""
        return "\n".join(_favicon._compact_lines(_favicon.run(target)))

    @app.tool(description=guides.SECRETS_SCAN)
    def secrets_scan(path: str, max_size: int = 1_000_000) -> str:
        """Scan a file/dir for leaked secrets (API keys, tokens, private keys) as
        file:line. Findings are REAL secrets — handle carefully. Compact text."""
        return "\n".join(_secrets_scan._compact_lines(_secrets_scan.run(path, max_size=max_size)))

    @app.tool(description=guides.DECOMPILE)
    def decompile(binary: str, function: str = "", all: bool = False) -> str:
        """Decompile a binary to pseudo-C via Ghidra headless. Default lists the
        function map; set `function` (name/address) or all=true. See the tool
        description for interpreting stripped/packed binaries. Returns compact text."""
        mode = "func" if function else "all" if all else "list"
        res = _decompile.run(binary, mode=mode, target=function)
        return "\n".join(_decompile._compact_lines(res))

    @app.tool(description=guides.DISASM)
    def disasm(file: str, function: str = "", all: bool = False, syntax: str = "intel",
               raw: bool = False, arch: str = "x86-64", base: int = 0x1000,
               offset: int = 0) -> str:
        """Disassemble a binary (objdump) or raw blob (capstone, raw=true). See the
        tool description for modes and raw-arch selection. Returns compact text."""
        mode = "func" if function else "all" if all else "list"
        res = _disasm.run(file, mode=mode, target=function, syntax=syntax,
                          raw=raw, arch=arch, base=base, offset=offset)
        return "\n".join(_disasm._compact_lines(res))

    @app.tool(description=guides.BINDIFF)
    def bindiff(old: str, new: str, context: int = 3, max_funcs: int = 50) -> str:
        """Diff two binaries function-by-function to find a security patch. See the
        tool description for reading the diffs. Returns compact text."""
        res = _bindiff.run(old, new, context=context, max_funcs=max_funcs)
        return "\n".join(_bindiff._compact_lines(res))

    @app.tool(description=guides.PWN_TEMPLATE)
    def pwn_template(binary: str, host: str = "", port: int = 0) -> str:
        """Generate a pwntools exploit skeleton from an ELF (protections + strategy +
        script). See the tool description for the strategies. Returns compact text."""
        info = _pwn_template.analyze(binary)
        script = _pwn_template.generate_script(info, host=host, port=port)
        return "\n".join(_pwn_template._compact_lines(info, script))

    @app.tool(description=guides.GADGETS)
    def gadgets(file: str, search: str = "", all: bool = False, max_insns: int = 5,
                raw: bool = False, arch: str = "x86-64", base: int = 0x400000) -> str:
        """Find & categorize ROP/JOP gadgets. Use `search` (regex) to find specific
        ones (e.g. "pop rdi"). See the tool description for chain-building. Compact text."""
        res = _gadgets.run(file, raw=raw, arch=arch, base=base, max_insns=max_insns,
                           search=search)
        return "\n".join(_gadgets._compact_lines(res, all))

    @app.tool(description=guides.SYMBOLIC)
    def symbolic(binary: str, find: str, avoid: str = "", argv: bool = False,
                 input_size: int = 32, max_steps: int = 300) -> str:
        """Solve for input that reaches `find` (address or stdout string) via angr.
        Set argv=true for argv[1] input. See the tool description. Returns compact text."""
        res = _symbolic.run(binary, find=find, avoid=avoid, argv=argv,
                            input_size=input_size, max_steps=max_steps)
        return "\n".join(_symbolic._compact_lines(res))

    @app.tool(description=guides.FIRMWARE)
    def firmware(file: str, extract: bool = False, recursive: bool = False) -> str:
        """Scan/unpack firmware with binwalk and triage the contents (creds, keys,
        configs, binaries, hardcoded secrets). See the tool description. Compact text."""
        res = _firmware.run(file, extract=extract, recursive=recursive)
        return "\n".join(_firmware._compact_lines(res))

    @app.tool(description=guides.LOG_TRIAGE)
    def log_triage(file: str, top: int = 15) -> str:
        """Triage an auth/web log: brute force, web attacks, scanners, anomalies.
        See the tool description for interpretation. Returns compact text."""
        return "\n".join(_log_triage._compact_lines(_log_triage.run(file, top=top)))

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
