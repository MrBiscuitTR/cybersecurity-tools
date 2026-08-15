"""Operator guidance strings surfaced to the LLM as MCP tool descriptions.

Design intent: the model driving these tools may be small and may not know the
current flags/output of every CLI, or the intuition an experienced operator has.
So each guide is written to *teach*: what the tool is for, when to reach for it,
exactly what the output looks like and how to read it, what to do next, and how
to recover from failures. Kept information-dense but not cramped — the model
should genuinely "get it", while respecting a limited context window.

Each constant is one tool's description. Keep them in sync with the tool.
"""

SUBDOMAINS = """\
Passive subdomain enumeration for a domain. Queries 8 free public sources at once
(crt.sh, certspotter, hackertarget, wayback, urlscan, subdomain.center, rapiddns,
alienvault OTX), de-duplicates, and returns one compact set. Fully passive: it
talks to those third-party APIs, NOT to the target. Safe to run first, always.

WHEN TO USE
  First step of recon on any domain. Run before port scanning or content
  discovery — it tells you which hosts even exist. Re-run with resolve=true to
  narrow a big list down to hosts that are actually live right now.

INPUT
  domain: the apex/registrable domain, e.g. "example.com". Do NOT pass a URL,
  a path, or a subdomain like "www.example.com" (it's normalized, but apex is
  cleanest). resolve: set true to keep only names with a DNS A record (adds IPs).

OUTPUT (text mode) — read it like this:
  Line 1:  "# example.com  502 subdomains  (5/8 sources hit)"
           -> total unique count and how many sources responded. 5/8 is normal.
  Line 2:  "# sources: certspotter=3, crtsh=0, subdomaincenter=498, ..."
           -> per-source hit counts. crtsh=0 usually means crt.sh was down (it
              often 502s), NOT that there are no certs. One big number (like
              subdomaincenter=498) carrying the result is normal and fine.
  Line 3:  "# down: crtsh, otx, wayback"  -> sources that failed/returned nothing.
  Then:    one hostname per line, sorted. With resolve=true: "host  1.2.3.4".

HOW TO INTERPRET
  - Expect noise: passive sources include dead, wildcard (*.example.com), and
    junk-looking hosts (IPs-as-labels, hex blobs). That's the source data, not a
    bug. Don't discard them blindly — a weird host can be the interesting one.
  - Few or zero results with most sources "down" -> transient API outages, not a
    small attack surface. RETRY once; the mix of live sources changes minute to
    minute (this is exactly why 8 sources are used).
  - A count of 0 with sources hitting -> the domain genuinely has little public
    footprint, or you passed the wrong apex.

WHAT TO DO NEXT
  - Feed the host list into subdomain-takeover detection, or into content
    discovery / port scanning on the Kali box (ffuf, nmap, httpx).
  - Use resolve=true to prioritize live hosts before spending time on them.
  - Cross-reference odd hostnames (staging., dev., internal., vpn., admin.) —
    these are high-value and worth looking at first.

FAILURE / RETRY
  - Never errors on a dead source; it just marks it "down". If MANY are down and
    the count looks too low, wait and retry once. hackertarget and otx are
    rate-limited (~50/day, 429) — their being down is expected, not alarming.
"""

TAKEOVER = """\
Subdomain-takeover detection. Enumerates a domain's subdomains (or takes a host
list), resolves each name's CNAME, and flags records that point at a third-party
service (GitHub Pages, S3, Heroku, Azure, ...) whose resource looks unclaimed —
the classic dangling-DNS takeover. Passive: DNS via DoH; with confirm=true it
does ONE GET per candidate to read the provider's error page. It never claims or
attacks anything.

WHEN TO USE
  Right after subdomain enumeration. This is the highest-value quick win in
  recon: a confirmed takeover means you can serve content on someone's subdomain.
  Pass a domain to do enum+check in one shot, or pass hosts if you already enumerated.

INPUT
  domain: apex to enumerate then check (e.g. "example.com"), OR
  hosts:  a list you already have. confirm: set true to fetch each candidate's
  page and match the provider's "unclaimed" fingerprint (more signal, a little slower).

OUTPUT — read it like this:
  Line 1: "# takeover: checked 22 hosts  high=0 medium=1 low=3"
          -> how many hosts, bucketed by confidence. Focus on HIGH first.
  Then one line per noteworthy host:
    "[HIGH] blog.example.com -> victim.github.io (GitHub Pages) DANGLING FP-MATCH"
  Flags: DANGLING = the CNAME target itself returns NXDOMAIN (nothing there — the
  strongest signal). FP-MATCH = the served page matched the provider's unclaimed-
  resource text. edge-service = this provider is only claimable in some setups.

CONFIDENCE — this is the key intuition:
  HIGH   = actionable. A claimable service AND (dangling OR fingerprint matched).
           Verify, then it's very likely a real takeover.
  MEDIUM = one signal only, or a conditionally-claimable service. Worth a manual look.
  LOW    = the host CNAMEs to a known service but that service currently RESOLVES
           and SERVES a real page. NOT exploitable as-is — it's a live, legit
           setup. Informational. Do NOT report a LOW as a finding. (Example: a
           subdomain pointing at a live GitHub Pages blog shows up LOW — that's
           correct and expected, not a vulnerability.)

WHAT TO DO NEXT
  - For HIGH/MEDIUM: re-run with confirm=true if you haven't, to get the FP-MATCH
    signal, then verify manually before claiming anything.
  - Hosts with no CNAME to a fingerprinted service are silently skipped (not shown)
    — that's correct; they aren't takeover-shaped.

FAILURE / RETRY
  Only hosts with a CNAME to a service in the fingerprint table are reported. An
  empty result ("no CNAMEs pointing at fingerprinted services found") means no
  takeover surface via known providers — a clean result, not an error.
"""

DNS_RECORDS = """\
Full DNS record dump for a domain PLUS a zone-transfer (AXFR) attempt, in one
call. Pulls A/AAAA/NS/MX/TXT/SOA/CNAME/CAA via privacy-first DoH, then tries an
AXFR against each authoritative nameserver. Read-only recon.

WHEN TO USE
  Early recon on a domain, alongside subdomain enumeration. The record dump maps
  mail (MX), infrastructure (NS/A), and policy (TXT/SPF/DMARC, CAA). The AXFR
  attempt is a cheap shot at a high-value misconfiguration.

INPUT
  domain: apex (e.g. "example.com"). axfr: set false to skip the transfer attempt
  (e.g. when you only want records, or outbound TCP:53 is firewalled).

OUTPUT
  "TYPE   value" lines grouped by record type, then a "## zone transfer (AXFR)"
  section marked either "VULNERABLE" or "refused (good)":
    "[OPEN] ns1... -> N records LEAKED"  followed by the leaked records, OR
    "[ok]   ns1...: refused/empty"       (the normal, secure case).

HOW TO INTERPRET
  - AXFR success ([OPEN]) is a real finding: the nameserver hands its entire zone
    to anyone, exposing every internal/hidden host at once. Capture the records.
  - AXFR "refused/empty" is the CORRECT, secure behavior — not an error.
  - TXT records reveal SPF/DMARC/verification tokens (useful for spoofing posture
    and for spotting third-party services in use). CAA shows which CAs may issue.
  - AXFR needs outbound TCP:53; a "PermissionError"/timeout in error usually means
    a firewall on YOUR side, not that the server refused — retry from an unfiltered host.

WHAT TO DO NEXT
  - Feed A/NS/MX hosts and any AXFR-leaked names into further enumeration.
  - If AXFR is open, you likely have the full internal namespace — prioritize it.
"""

HTTP_PROBE = """\
Probe hosts over HTTP(S) and return one compact line per LIVE host: status, page
title, server banner, redirect target, content length, and a technology guess.
This is the triage step between "I have a big host list" and "these few are worth
my time". Read-only GETs; no fuzzing, no payloads.

WHEN TO USE
  Right after subdomain enumeration. Pass a single host, an explicit list, or a
  domain with enum=true to enumerate subdomains first and probe them all in one
  shot. Run it before spending effort on any host — it tells you what's alive and
  what it is.

INPUT
  target: a host to probe, OR a domain when enum=true (enumerate then probe all).
  hosts: an explicit list you already have. show_dead: also list non-responding
  hosts. timeout: per-request seconds.

OUTPUT — header then one line per live host:
  "# http_probe: 23 targets, 21 live"
  'https://vault.example.com/  [200]  "Vaultwarden Web"  server=cloudflare  len=23139  [tech: cloudflare]'
  'https://www.example.com/  [200]  "Home"  server=nginx  -> https://example.com/  [tech: nginx]'
  Fields: the working scheme+url, [HTTP status], "page title", server=, len=,
  "-> final_url" if it redirected, and [tech: ...] fingerprint. Dead hosts are
  hidden unless show_dead.

HOW TO INTERPRET — what to look at first:
  - Titles and tech are the fastest signal. Interesting titles (admin, login,
    dashboard, vault, staging, dev, internal, jenkins, grafana, phpmyadmin) and
    unusual tech are priority targets.
  - Status: 200 = content; 401/403 = auth-gated (often the juicy stuff); 301/302
    with "->" shows where it really lives; 500/502/503/525 = broken origin (still
    a real host, maybe a takeover or a dev box that's down).
  - server= and tech reveal the stack to tailor the next step (WordPress -> wpscan,
    IIS -> Windows, etc.).

WHAT TO DO NEXT
  - Feed interesting live hosts into tls_audit (headers/TLS), directory brute
    forcing (ffuf/gobuster on the box), or a manual look.
  - 401/403 hosts: try default creds, path bypasses, or note for later.
  - Redirects to a different host/domain can reveal new scope.

FAILURE / RETRY
  A host with no line (and not shown) simply didn't respond on 80/443 — it may
  still have services on other ports (check with nmap). enum=true needs the domain
  to resolve and have findable subdomains.
"""

JWT = """\
Decode, audit, verify, forge, and attack JSON Web Tokens. One tool with an
`action` argument — PICK THE ACTION, then pass ONLY that action's fields (getting
the field:value pairs right matters; see each action below). Local crypto only,
nothing is sent anywhere. Supports algs: none, HS256/384/512, RS256/384/512,
PS256/384/512, ES256/384/512, EdDSA.

CHOOSE THE ACTION:
  action="decode"  (default)  fields: token
      Decode header+claims, decode exp/iat/nbf, and list weaknesses/attack surface.
      START HERE for any token you're handed. No key needed.
  action="verify"             fields: token, and ONE of: secret (HS*) | key_pem (RS/PS/ES/EdDSA public key PEM text)
      Check whether a signature is valid for a given key. Use secret for HS*,
      key_pem (public key) for the asymmetric families.
  action="sign"               fields: alg, payload (JSON string), and ONE of: secret | key_pem (PRIVATE key PEM); optional header (JSON string)
      Forge a token. HS*/none use secret; RS/PS/ES/EdDSA use key_pem (private key).
  action="crack"              fields: token, wordlist (path to a wordlist file)
      Brute-force an HS* secret. Only works on HS* tokens.
  action="attack"             fields: token; optional public_key_pem, wordlist
      Auto-run every applicable attack and return forged token candidates:
      alg=none variants (always), RS->HS confusion (if you pass public_key_pem =
      the server's RS/EC PUBLIC key PEM), and weak-secret crack (if you pass a wordlist).

OUTPUT
  decode: header + payload JSON, decoded timestamps, then "## FINDINGS" ranked
    HIGH/MEDIUM/INFO (e.g. alg=none, jku/x5u/jwk headers, kid injection, no exp).
  verify: "# verify: VALID/INVALID  alg=..  (reason)".
  sign: the token string on stdout.
  crack: the recovered secret or "not found".
  attack: each candidate as "## <attack>" + the forged token + a note on when it works.

HOW TO INTERPRET / THE INTUITION:
  - alg=none HIGH means: if the server accepts unsigned tokens, use the attack
    action's none token to become anyone. Try all case variants (none/None/NONE).
  - HS* token + you suspect a weak key -> crack with a wordlist (rockyou), then sign
    a new token with role/admin claims using the found secret.
  - Server normally uses RS*/ES* but verifies sloppily -> RS->HS confusion: pass the
    server's PUBLIC key as public_key_pem; the forged token is signed with HMAC using
    that public key bytes as the secret. Works only if the server feeds the RS pubkey
    into an HS verifier (a real, common bug).
  - Header jku/x5u = the server may fetch keys from a URL you control (host your own
    JWKS -> sign with your key). jwk = embedded key some libs blindly trust. kid =
    often concatenated into a file path or SQL query (try ../ traversal, SQLi).
  - To escalate: decode -> change the interesting claim (user/role/is_admin/sub) ->
    re-sign (weak secret) or forge (none/confusion) -> replay against the server.

WHAT TO DO NEXT
  - Take a forged/re-signed token and replay it in the app's Authorization header
    (only against an authorized target) to confirm the bypass.
  - A JWT found by js_recon or in a capture feeds straight into decode/attack here.

FAILURE / RETRY
  "not a JWS/JWT (3 parts)" -> the value isn't a token (maybe it's URL-encoded or a
  JWE with 5 parts — this tool handles signed JWS/JWT, not encrypted JWE). verify
  INVALID just means wrong key/alg — try the other key type or the confusion attack.
"""

JS_RECON = """\
Mine a website's JavaScript for endpoints, secrets, and interesting parameters.
Fetches the page, pulls in its linked + inline scripts, and greps the JS for API
paths, leaked credentials (API keys, tokens, private keys), and parameter names
worth probing. LinkFinder + SecretFinder in one call. Read-only.

WHEN TO USE
  On any web target with a real front-end. Modern apps hide their whole API surface
  in JS bundles — this pulls out the endpoints to test and any secrets baked into
  the client. Run it after http_probe flags a live, interesting web host.

INPUT
  target: a page URL (its <script src> + inline scripts are discovered and fetched)
  OR a direct .js URL (analyzed alone). only_secrets: report just the secrets.

OUTPUT — sections:
  "# js_recon: URL  (5 scripts, 34 endpoints, 2 secrets, 3 params)" summary line.
  "## SECRETS" — "[type] value  (in app.js)". Types include aws-access-key,
  google-api-key, github-token, stripe-secret, slack-token, jwt, private-key,
  generic-secret, etc.
  "## endpoints" — API paths and absolute URLs found (static assets filtered out).
  "## interesting params" — names like token/auth/admin/redirect/is_admin.

HOW TO INTERPRET
  - SECRETS are the headline. A live key (AWS, Stripe, GitHub, Slack) is often
    directly usable — but VERIFY: front-end keys are sometimes public/scoped by
    design (e.g. a Google Maps browser key, a Stripe *publishable* pk_). A secret
    key (sk_live, private-key, aws-secret) leaking client-side is a real finding.
  - endpoints map the API surface: look for /admin, /api/internal, /debug, version
    prefixes, and paths that take ids/params. These are your next targets.
  - interesting params hint at features to fuzz (redirect= for open redirect/SSRF,
    is_admin/role for authz, token/jwt for auth).

WHAT TO DO NEXT
  - Probe discovered endpoints (curl/ffuf) — especially unauthenticated admin/debug.
  - Feed a discovered JWT into the jwt tool; feed secrets into the matching service
    (aws sts get-caller-identity, etc.) to confirm validity — only if authorized.
  - New hostnames in the endpoints feed back into subdomain recon.

FAILURE / RETRY
  0 scripts can mean a server-rendered site (scan the page HTML — it still does) or
  a heavy SPA that injects scripts at runtime (point it at the bundle URL directly).
  Secrets found here are REAL — handle carefully, never commit them.
"""

TLS_AUDIT = """\
Audit a host's TLS configuration and HTTP security headers in one call. Reports
the negotiated protocol/cipher, which TLS versions the server accepts (flagging
deprecated TLS 1.0/1.1), the leaf certificate (subject/issuer/SANs/expiry,
validity, self-signed), the presence/absence of key security headers, and whether
plain HTTP upgrades to HTTPS. Read-only; sends no payloads.

WHEN TO USE
  Auditing any HTTPS service: quick TLS hygiene + header posture without juggling
  openssl s_client and curl -I flags. Good on web hosts found during recon.

INPUT
  target: host or host:port (default 443), e.g. "example.com" or "example.com:8443".
  version_probe: set false to skip per-version probing (faster; you lose the
  deprecated-TLS check). timeout: per-connection seconds.

OUTPUT — top lines are facts, then "## FINDINGS" ranked HIGH/MEDIUM/LOW:
  "# negotiated: TLSv1.3 TLS_AES_256_GCM_SHA384"  -> what got used.
  "# versions accepted: TLSv1.2, TLSv1.3"          -> everything the server allows.
  "# cert: subject=... issuer=... expires=YYYY-MM-DD (Nd) valid_chain=True/False".
  "# server: '...'  http->https: True/False".
  FINDINGS lines like "[HIGH] certificate EXPIRED", "[MEDIUM] deprecated TLSv1.0
  accepted", "[MEDIUM] missing header content-security-policy".

HOW TO INTERPRET
  - valid_chain=False with an expired/self-signed note is a real TLS problem.
    days_to_expiry < 21 is worth flagging even on a valid cert.
  - Deprecated versions accepted (TLS 1.0/1.1) = weak config even if 1.3 also works.
  - Missing HSTS/CSP are MEDIUM; missing X-Frame-Options/nosniff/referrer/permissions
    are LOW. "http->https: False" means the site is reachable over plaintext.
  - No FINDINGS ("(none)") means clean TLS + all checked headers present — good.

WHAT TO DO NEXT
  - For weak TLS, confirm cipher/curve details with `nmap --script ssl-enum-ciphers`
    or `sslscan` on the box for a deeper view.
  - Missing headers feed directly into a web-app finding write-up.
"""

TRIAGE = """\
Static triage of a suspicious FILE — a compact structured report an LLM can reason
over. Runs fully static (never executes the sample): hashes, file type, entropy,
extracted strings bucketed into IOCs, deep PE analysis (pefile) or an ELF header
read, and a ranked list of red flags. Works on any file.

WHEN TO USE
  You have a binary/sample/dropped file and want to know what it is and whether
  it's malicious, fast — before (or instead of) opening a disassembler. Great first
  pass; pairs with your own reading of the disassembly for anything interesting.

INPUT
  file: path to the sample. min_str: min string length (default 4; raise to cut
  noise). max_strings: cap on sample strings returned.

OUTPUT — read top-down:
  "# type: PE/DOS executable  size: 360448  entropy: 6.483" and the SHA256/MD5/SHA1.
  "## RED FLAGS" — the ranked judgement calls; read these first. Examples: high
  whole-file or per-section entropy (packed/encrypted), RWX sections, a section
  with virtual size but no raw data (unpacks at runtime), suspicious API imports,
  TLS callbacks (code before entry point), suspicious strings, embedded network IOCs.
  "## PE ..." — machine/subsystem/entry/imphash/compile-time, then a section table
  (name vsize rawsize entropy flags) and the suspicious import list.
  "## ELF ..." — class/endian/type/machine/entry/interp.
  "## urls/ips/domains/registry/win_paths/emails" — extracted IOCs.

HOW TO INTERPRET — the intuition:
  - Entropy > ~7.2 (whole file or a section) almost always means packed/encrypted
    (UPX, a crypter). A tiny import table + one big high-entropy section is the
    classic packed look — expect to unpack before deeper analysis.
  - imphash lets you cluster/compare against known families. compile_time can be
    faked (many samples show 2001/1970/absurd dates) — treat as a weak signal.
  - Suspicious imports tell you capability: VirtualAlloc+WriteProcessMemory+
    CreateRemoteThread = process injection; InternetOpen/URLDownloadToFile =
    downloader; RegSetValue = persistence; IsDebuggerPresent = anti-analysis.
  - RWX section or "virtual size but no raw data" = self-modifying/unpacking.
  - A benign OS binary also imports some of these — weigh the WHOLE picture
    (entropy + imports + strings + IOCs), not any one flag.

WHAT TO DO NEXT
  - Packed? unpack (UPX -d, or run in a sandbox and dump) then re-triage.
  - Copy the SHA256 to check reputation/VT out of band; copy IOCs into your notes.
  - For real analysis, open it in Ghidra/objdump and read the code around the entry
    point and the suspicious imports — you (the model) are good at pseudo-C.

FAILURE / RETRY
  "PE: pefile not installed" -> the generic report still works; install pefile for
  the section/import detail. "file not found" -> bad path. Handle real samples in an
  isolated VM; this tool only reads, but downstream steps may execute.
"""

PCAP = """\
Analyze a pcap/pcapng capture (wraps tshark). Three modes, all read-only on a
capture FILE (never live): DIGEST (default, compact multi-section overview),
FOLLOW a single reassembled TCP/UDP stream, or run any Wireshark display FILTER.
The digest is kilobytes even for a big capture, so it fits your context window;
the other two modes let you drill into specifics.

WHEN TO USE
  Any time you have a capture. Start with the digest to see what's there, then
  follow a stream or run a filter to dig in. Handles Ethernet AND monitor-mode
  (802.11) captures, VLAN, QUIC, TLS, etc. — anything Wireshark can dissect.

MODE 1 - DIGEST (call with just `file`, optionally `sections`)
  Sections (auto-skip when empty, so absence is itself information):
    summary   packets, duration, and the list of protocols present
    proto     protocol hierarchy (indent = encapsulation depth; frames/bytes/layer)
    hosts     NETWORK INVENTORY: IP <-> MAC <-> hostname, correlated from Ethernet,
              ARP, DHCP, and DNS. The "what's on this network" map.
    flows     top TCP/UDP flows as "proto/STREAMID  a <-> b  pkts/bytes  SNI".
              The STREAMID is what you pass to follow a stream.
    tls       TLS/QUIC SNI (server names contacted, with hello counts) + versions.
              On an all-HTTPS capture this is your main intel: who was contacted.
    dns       DNS queries -> answers.
    http      requests/responses + user-agents seen + server banners.
    dhcp      DHCP leases: MAC, hostname, IP, vendor class (device fingerprinting).
    files     filenames/objects transferred over HTTP/SMB/TFTP/FTP.
    voip      SIP signaling (method/parties/status) + RTP stream quality (loss/jitter).
    services  service/host discovery: mDNS, LLMNR, NBNS, SSDP.
    arp       ARP who-has/is-at (L2 host map; also useful on monitor-mode captures).
    wifi      802.11 beacons + probe requests. HIDDEN (cloaked) SSIDs are uncovered
              by correlating the BSSID with probe-responses/association-requests
              ([SSID REVEALED]). Also flags captured WPA/WPA2 EAPOL handshakes
              (crackable offline). Appears only on monitor-mode captures.
    creds     LOOT, labeled and paired where possible. Lines look like
              "[kind] user=..  password=..  host=..  hash=..  (note)". Kinds:
              cleartext logins (ftp/imap/pop/telnet/http-basic, user+password
              paired); SNMP community strings; net-NTLM hashes (ntlmv1/v2, with
              hash= and the hashcat mode in the note); Kerberos (kerberoast-spn =
              a roastable SPN; kerberoast/asrep-roast = a ready $krb5tgs$/$krb5asrep$
              hash when the ticket cipher was captured). SMB shares/files appear in
              the "files" section (e.g. [smb-share] for a UNC path).
  Narrow with sections (e.g. "creds,hosts,files") on large captures to save tokens.

  KEY LOOT TO ACT ON:
    "[ntlmv2] user=.. hash=user::DOMAIN:chal:proof:blob  (hashcat -m 5600)" is a
    ready-to-crack hash — save the hash= value and run the noted hashcat mode.
    "[kerberoast-spn] spn=MSSQL/db01" is a kerberoast target (request+crack a TGS).
    Paired "[ftp] user=.. password=.." / "[imap] ..." are often directly usable.

MODE 2 - FOLLOW A STREAM (set `stream`)
  stream="5" follows TCP stream 5; stream="udp:3" follows UDP stream 3. Returns the
  reassembled content (ascii). This is "Follow TCP Stream" — use it to read a full
  HTTP exchange, an FTP-DATA transfer, an SMTP session, etc. (CLI adds --hex for
  binary streams.)

MODE 3 - DISPLAY FILTER (set `dfilter`)
  dfilter is any Wireshark display filter, e.g. "http.request && ip.addr==10.0.0.5",
  "dns.qry.name contains vpn", "tcp.flags.syn==1 && tcp.flags.ack==0" (SYN scan),
  "arp", "wlan.fc.type_subtype==0x04". Returns matching packets as one-line summaries.
  This is the escape hatch for anything the digest sections don't surface.

HOW TO INTERPRET
  - All-TLS capture with empty http/creds is normal — payloads are encrypted; the
    `tls` SNI list still tells you WHO was contacted even though content is opaque.
  - creds is HEURISTIC: http-authorization is base64 (decode for user:pass); treat
    every hit as a lead to confirm by following that stream, not as proof.
  - flows is sorted by bytes; the biggest flows are usually the interesting content
    transfers. Grab a flow's stream id and follow it.

WHAT TO DO NEXT
  - From flows/tls: follow the stream id of an interesting conversation.
  - From a suspicious DNS/SNI host: pivot into the recon tools (enum_subdomains).
  - Need something specific (a scan pattern, a protocol, one host): use a filter.

FAILURE / RETRY
  "error: tshark not found" -> install tshark (apt install tshark on Kali) or pass
  its path. "error: capture not found" -> bad file path. A filter that matches
  nothing returns "matched 0" (not an error).
"""
