# External sources this repo relies on

Every outside dependency — HTTP APIs, external binaries, and pip packages — in
one place. Keep this current when adding a tool. All APIs listed are **free and
no-auth** unless noted.

## HTTP APIs

### DNS-over-HTTPS resolvers (`common/dns.py`)
Privacy-first order; **Google is deliberately not used**. RFC 8484 wireformat.

| Provider | Endpoint | Notes |
| --- | --- | --- |
| Quad9 | `https://dns.quad9.net/dns-query` | preferred |
| Mullvad | `https://dns.mullvad.net/dns-query` | fallback |
| Cloudflare | `https://cloudflare-dns.com/dns-query` | last-resort fallback |

### Subdomain enumeration sources (`recon/subdomains.py`)
8 independent sources; any may be down at any time (that's why there are 8).

| Source | Endpoint | Notes |
| --- | --- | --- |
| crt.sh | `https://crt.sh/?q=%25.<d>&output=json` | CT logs; frequently 502/slow |
| Cert Spotter | `https://api.certspotter.com/v1/issuances` | CT logs; reliable |
| HackerTarget | `https://api.hackertarget.com/hostsearch/` | passive DNS; ~50 req/day free |
| Wayback | `http://web.archive.org/cdx/search/cdx` | archived URLs; slow, broad |
| urlscan.io | `https://urlscan.io/api/v1/search/` | scan history |
| subdomain.center | `https://api.subdomain.center/` | aggregated |
| RapidDNS | `https://rapiddns.io/subdomain/` | passive DNS; HTML scrape |
| AlienVault OTX | `https://otx.alienvault.com/api/v1/indicators/domain/.../passive_dns` | rate-limited (429), backs off |

### Takeover fingerprint pages (`recon/takeover.py`, `--confirm` only)
No dedicated API — fetches the candidate host's own root page (HTTPS/HTTP) to
match a provider's "unclaimed resource" text. DNS via the DoH resolvers above.

### Zone transfer / TLS audit (`recon/dns_records.py`, `web/tls_audit.py`)
No third-party API — these connect directly to the target: AXFR over TCP:53 to the
domain's authoritative nameservers (`dns_records`), and a TLS handshake + HTTP(S)
request to the target host (`tls_audit`). DNS lookups still use the DoH resolvers.

## External binaries (wrapped via `common/proc.py`, read-only)

| Binary | Used by | Install on Kali | Notes |
| --- | --- | --- | --- |
| `tshark` | `forensics/pcap.py` | `apt install tshark` | Wireshark CLI. On the Windows dev host: `C:\Program Files\Wireshark\tshark.exe` (pass `--tshark`). |

Planned tools will additionally wrap common Kali/RE tooling already on the box:
`strings`, `xxd`/`hexdump`, `strace`, `ltrace`, `file`, `grep`, `tmux`. Each is
documented at the top of the tool that uses it.

## Python packages (`requirements.txt`)

| Package | Why | Used by |
| --- | --- | --- |
| `mcp` | MCP server exposing tools to the LLM | `mcp_server/` |
| `cryptography` | parse leaf certs (incl. invalid ones) | `web/tls_audit.py` |
| `pefile` | deep PE analysis (optional) | `malware/triage.py` |
| `pytest` | tests | `tests/` |

**Not used on purpose:** HTTP is stdlib `urllib` (no `requests`); DNS is a stdlib
wireformat DoH client (no `dnspython`). This keeps the recon/DNS core
dependency-free and portable to the Kali VM.
