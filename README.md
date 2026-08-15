# cybersecurity-tools

AI-operated security tooling that fills the gaps Kali leaves — fast enumeration,
recon, OSINT, and API-driven tasks — designed to be driven by a local LLM through
an MCP server. Python 3.12.

> **Not a Kali alternative.** The operator already has nmap, ffuf, hashcat, tshark
> and friends. This repo is for the things Kali *doesn't* do easily: flaky-API
> enumeration (crt.sh + fallbacks), multi-step recon chains, and wrapping tools so
> an LLM gets the complete raw output to reason over. No port-scanner or
> hashcat/John clones, no shipped wordlists.

See **[docs/VISION.md](docs/VISION.md)** for the why, **[docs/CONVENTIONS.md](docs/CONVENTIONS.md)**
for how every tool is built, and **[docs/EXTERNAL.md](docs/EXTERNAL.md)** for every
external API/binary/package the repo depends on. New tools start from
**[TEMPLATE.py](TEMPLATE.py)**.

Privacy note: DNS uses privacy-first resolvers (Quad9 → Mullvad → Cloudflare,
never Google) and HTTP/DNS run on the stdlib (no `requests`/`dnspython`).

## Design principles

Every tool obeys these (full detail in [docs/CONVENTIONS.md](docs/CONVENTIONS.md)):

1. **Executable *and* importable.** Logic lives in documented functions that
   return data; a `main(argv=None)` handles CLI. Guarded `if __name__ == "__main__"`.
2. **Help everywhere.** `-h`/`--help` on every tool. Run with no args (when args
   are required) → prints usage and points at `--help`, exits non-zero. Never hangs.
3. **Built for an AI reader.** Complete output, never truncated or paginated.
   `--json` for machine parsing (default for AI use), human table otherwise.
   Results → stdout, logs/errors → stderr. No interactivity, no color-as-meaning.
4. **Documentation is the interface.** Module + function docstrings say what a
   tool does, when to use it, what it returns, and what it will *not* do. Any
   external **API** is noted at the top of the file (endpoint, auth, rate limits).
5. **Minimal dependencies.** Standard library first; every third-party import is
   justified in [requirements.txt](requirements.txt). Secrets come from env vars.
6. **No destructive actions — ever — on this machine or on targets.** Read-only by
   default; active modes are opt-in flags and still non-destructive. See
   [docs/scope.md](docs/scope.md).

## Layout

| Folder | Domain | Example tools |
| --- | --- | --- |
| [network/](network/) | Hosts, packets, protocols | protocol probes, wrappers over `tshark`/pcap |
| [web/](web/) | HTTP(S) applications | header/TLS audit, favicon-hash lookup, endpoint checks |
| [recon/](recon/) | Enumeration & info gathering | subdomain enum (crt.sh + fallbacks), DNS/RDAP sweeps |
| [crypto/](crypto/) | Ciphers, hashes, encoding | hash ID, cipher solvers, crypto-flaw inspection helpers |
| [passwords/](passwords/) | Credential *analysis* | strength/entropy scoring (no cracker clones) |
| [forensics/](forensics/) | Artifacts & captures | metadata/log parsing, pcap readers for AI consumption |
| [malware/](malware/) | Static triage only | PE/ELF headers, strings, imports, IOC extraction |
| [reversing/](reversing/) | Reverse engineering | decompile, disasm, bindiff, gadgets, symbolic, firmware, pwn-template |
| [cloud/](cloud/) | Cloud attack surface | S3/GCS/Azure bucket hunting, AWS IAM enumeration |
| [analyze/](analyze/) | AI reasoning layer | binary → prioritized exploitation action plan |
| [common/](common/) | Shared helpers | HTTP (stdlib), JSON/compact output, validators, subprocess capture |
| [mcp_server/](mcp_server/) | MCP server for the LLM operator | exposes tools + teaching-style usage guides |
| [data/](data/) | Tiny fixtures only | (big lists live on the Kali box, passed by path) |
| [docs/](docs/) | Vision, conventions, scope | |
| [tests/](tests/) | Test suite mirroring the layout | |

## Usage

Run tools as modules from the repo root so `common/` is importable:

```bash
python -m recon.subdomains example.com --json     # AI-friendly, complete output
python -m recon.subdomains --help                 # every tool has -h/--help
```

Import them for composition:

```python
from recon.subdomains import run
data = run("example.com")
```

## MCP server

The primary interface for the LLM operator. It wraps each tool and returns
compact, context-window-friendly output, with a **teaching-style description per
tool** (see [mcp_server/guides.py](mcp_server/guides.py)) so a smaller model
knows how to read the output, what to do next, and when to retry.

### Setup (use a venv — keep it clean)

```bash
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install 'mcp<2' cryptography pefile capstone
# optional, only for specific tools:
#   pip install angr      # reversing/symbolic
#   pip install boto3     # cloud/iam_enum
```

> **`mcp<2` matters:** an unrelated `mcp` 2.0.0 on PyPI has no `fastmcp` and will
> fail to start. Pin `<2` (or `pip install fastmcp` — the server accepts either).

### Run

```bash
# stdio (default) — the client launches this and talks over stdin/stdout:
python -m mcp_server.server

# HTTP endpoint — reachable over the network at http://<host>:<port>/mcp:
python -m mcp_server.server --transport http --host 0.0.0.0 --port 8091
```

Point your MCP client at the stdio command, or the HTTP URL. Example stdio config:

```json
{ "mcpServers": { "cybersec": {
    "command": "python", "args": ["-m", "mcp_server.server"], "cwd": "/path/to/repo" } } }
```

The wrapper tools shell out to CLI tools that must be present on the host (Kali):
`nuclei`, `ffuf`, `binwalk`, `ghidra`/`analyzeHeadless`, `objdump`, `tshark`,
`ripgrep`, `git`. See [docs/EXTERNAL.md](docs/EXTERNAL.md).

## Setup

```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Scope

For systems you own or are authorized to test. See [docs/scope.md](docs/scope.md).
