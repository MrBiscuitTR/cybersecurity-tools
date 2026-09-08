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

### OSINT person sources (`osint/`)
Every capability has multiple sources; a dead one degrades the answer instead of
failing the run. All free and no-auth unless a key column says otherwise.

**Identity / accounts**

| Source | Endpoint | Notes |
| --- | --- | --- |
| ~70 platform profile URLs | e.g. `https://github.com/<u>` | `osint/username.py`. Presence checked with a random control handle per site to catch sites that 200 everything. |
| Gravatar profile | `https://gravatar.com/<sha256\|md5>.json` | Real name, bio, location + owner-verified linked accounts. Richest free per-address source. |
| Libravatar | `https://seccdn.libravatar.org/avatar/<md5>` | Federated Gravatar alternative. |
| GitHub search | `https://api.github.com/search/{users,commits}` | Commit-author email -> account. `GITHUB_TOKEN` optional but strongly recommended (unauthenticated search is throttled). |
| LinkedIn public profile | `https://www.linkedin.com/in/<vanity>` | `osint/linkedin.py` parses the embedded schema.org Person (career + education with dates). HTTP 999 = rate-limited, NOT absent. |

**Breach / exposure** (`osint/email.py`)

| Source | Endpoint | Notes |
| --- | --- | --- |
| XposedOrNot | `https://api.xposedornot.com/v1/check-email/` | free, no auth |
| Hudson Rock | `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email` | free, no auth; infostealer infections |
| LeakCheck public | `https://leakcheck.io/api/public?check=` | free, no auth; source names only |
| HaveIBeenPwned | `https://haveibeenpwned.com/api/v3/breachedaccount/` | `HIBP_API_KEY` (paid) |
| BreachDirectory | `https://breachdirectory.p.rapidapi.com/` | `RAPIDAPI_KEY` |

Metadata only — no credentials are retrieved or displayed. No SMTP `VRFY`/`RCPT`
probing is performed (unreliable, rude, and gets IPs blacklisted).

**Search engines** (`osint/websearch.py`) — 8 keyless + 4 keyed, queried in parallel
and merged by cross-engine agreement.

| Source | Endpoint | Notes |
| --- | --- | --- |
| DuckDuckGo | `html.duckduckgo.com/html`, `lite.duckduckgo.com/lite` | precise parsers |
| Bing / Brave / Startpage / Yahoo | their search pages | generic parser + redirect-wrapper decoding (Bing `u=a1<base64>`, Yahoo `/RU=`) |
| Mojeek, Marginalia | independent / indie-web indexes | |
| SearXNG | `$SEARX_URL` or a built-in list of public instances | Itself a meta-engine (Google/Bing/Brave/Wikipedia in one query) — the highest-value source here. Public instances rate-limit and mostly disable the JSON API, so several are tried; point `SEARX_URL` at your own (`http://localhost:8080`). |
| Brave API / Google CSE / Serper | official APIs | `BRAVE_API_KEY`, `GOOGLE_CSE_KEY`+`GOOGLE_CSE_CX`, `SERPER_API_KEY` |

**Public records** (`osint/records.py`)

| Source | Endpoint | Notes |
| --- | --- | --- |
| Wikidata | `https://www.wikidata.org/w/api.php`, `Special:EntityData/<QID>.json` | date of birth, birthplace, citizenship, education, employers, declared handles |
| Wikipedia | `https://en.wikipedia.org/api/rest_v1/page/summary/` | summary paragraph |
| SEC EDGAR | `https://efts.sec.gov/LATEST/search-index?q=` | full-text filing search. The SEC **requires** a contact User-Agent — set `SEC_CONTACT`. |
| GLEIF | `https://api.gleif.org/api/v1/lei-records` | legal entity name, status, registered address |
| Companies House | `https://api.company-information.service.gov.uk/search/officers` | `COMPANIES_HOUSE_KEY` |
| OpenCorporates | `https://api.opencorporates.com/v0.4/officers/search` | `OPENCORPORATES_API_KEY` |
| OpenSanctions | `https://api.opensanctions.org/search/default` | `OPENSANCTIONS_API_KEY` |

**Domain infrastructure** (`osint/infra.py`) — wraps `recon/` and `web/`, adds RDAP.

| Source | Endpoint | Notes |
| --- | --- | --- |
| RDAP | `https://rdap.org/domain/<d>`, `https://rdap.iana.org/domain/<d>` | registrar, creation/expiry, status, nameservers. Registrant identity is redacted for most TLDs post-GDPR. |
| RIPEstat | via `recon/asn.py` | IP -> ASN + announced netblocks |
| DoH resolvers | via `recon/dns_records.py` | A/AAAA/NS/MX/TXT/SOA/CNAME/CAA |
| TLS handshake | via `web/tls_audit.py` (`--active` only) | cert subject/issuer/SANs -> related domains and the legal org |
| HTTP probe | via `recon/http_probe.py` (`--active` only) | status, title, server banner, technology guess |

**Corporate ownership** (`osint/records.py`)

| Source | Endpoint | Notes |
| --- | --- | --- |
| GLEIF relationships | `https://api.gleif.org/api/v1/lei-records/<lei>/{direct,ultimate}-{parent,children}` | free, no auth. Parent/subsidiary links, self-reported and LOU-validated. A 404 means "no reported parent", not an error. |
| Companies House | `.../search/companies`, `.../company/<n>/officers` | `COMPANIES_HOUSE_KEY`. Executives with role, nationality, partial DoB, address. |

**No API** (`osint/contacts.py`) — phone and address extraction is pure computation
over text you already fetched: E.164 validation against the ITU-T calling-code
table, per-country postcode shapes, schema.org `PostalAddress` and microformats.
No libphonenumber dependency; anything ambiguous is labelled ambiguous.

**Vehicles** (`osint/vehicle.py`)

| Source | Endpoint | Notes |
| --- | --- | --- |
| NHTSA vPIC | `https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/` | free, no auth; VIN -> full spec |
| NHTSA recalls | `https://api.nhtsa.gov/recalls/recallsByVehicle` | free, no auth |
| DVLA VES | `https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles` | `DVLA_API_KEY`; vehicle data only, never owner data |

Plate -> owner is **not implemented**: those records are protected personal data
(DPPA 18 U.S.C. 2721 in the US, GDPR in the EU/UK, KVKK in Turkey) and no lawful
public API exposes them. Plate region/date decoding runs offline from built-in
tables (Turkish provinces, UK DVLA memory tags + age identifiers, German districts).

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
| `analyzeHeadless` (Ghidra) | `reversing/decompile.py` | `apt install ghidra` | Headless decompiler at `/usr/share/ghidra/support/analyzeHeadless`. Uses a bundled **Java** GhidraScript (no PyGhidra). Set `GHIDRA_HEADLESS` to override. |
| `objdump` (binutils) | `reversing/disasm.py` | preinstalled | Per-function disassembly. |
| `binwalk` (+ extractors) | `reversing/firmware.py` | `apt install binwalk squashfs-tools jefferson` | Firmware scan/extract. Extraction needs the extractor for each filesystem type. |
| `angr` (pip) | `reversing/symbolic.py` | `pip install angr` | Symbolic-execution solver. Heavy; runs the target in its own emulator. |
| `ripgrep` (rg) | `analyze/bughunt.py`, ad-hoc via `common/safe_bash.py` | `apt install ripgrep` | Fast code search for the vuln sweep. |
| `git` | `analyze/bughunt.py` (clone), `common/safe_bash.py` | preinstalled | Shallow-clones target repos. |
| `nuclei` | `recon/nuclei.py` | `apt install nuclei` | Template scanner; run `nuclei -update-templates` once. |

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

`playwright` is an **optional** extra used only by `osint/fetch.py:render()` for
JS-only pages; it is deliberately NOT in requirements.txt (it ships a ~150MB
browser). Everything in `osint/` works without it.

**Not used on purpose:** HTTP is stdlib `urllib` (no `requests`); DNS is a stdlib
wireformat DoH client (no `dnspython`). This keeps the recon/DNS core
dependency-free and portable to the Kali VM.
