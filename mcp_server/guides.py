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
    creds     LOOT: cleartext logins (HTTP/FTP/Telnet/IMAP/POP/SMTP), SNMP community
              strings, Kerberos principals/SPNs, and CRACKABLE net-NTLM hashes
              formatted for hashcat (v1=mode 5500, v2=mode 5600 — noted per line).
  Narrow with sections (e.g. "creds,hosts,files") on large captures to save tokens.

  KEY LOOT TO ACT ON: a "creds" line like
    "[ntlmv2] user::DOMAIN:chal:proof:blob  (hashcat -m 5600)"
  is a ready-to-crack hash — copy the value into a file and run the noted hashcat
  mode with a wordlist. SNMP community strings and IMAP/telnet logins are often
  directly usable. Kerberos SPNs are kerberoast targets.

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
