# recon

Information gathering, passive first.

Fits here: subdomain enumeration, DNS/WHOIS/RDAP lookups, certificate
transparency queries, email/username harvesting, metadata-based OSINT.

## Tools

- **[subdomains.py](subdomains.py)** — passive subdomain enumeration from 8 free
  no-auth sources at once (crt.sh, certspotter, hackertarget, wayback, urlscan,
  subdomain.center, rapiddns, OTX), de-duplicated. Tolerates any source being
  down. Optional `--resolve` keeps only live names.

  ```bash
  python -m recon.subdomains example.com
  python -m recon.subdomains example.com --resolve --json
  ```

- **[takeover.py](takeover.py)** — subdomain-takeover detection. Enumerates (or
  takes a host list), resolves CNAMEs, and flags dangling records pointing at
  claimable services (GitHub Pages, S3, Heroku, Azure, ...) against a fingerprint
  table. `--confirm` fetches each candidate's page to match the provider's
  unclaimed-resource text. Ranks HIGH/MEDIUM/LOW; LOW = live/legit, not exploitable.

  ```bash
  python -m recon.takeover example.com --confirm
  cat hosts.txt | python -m recon.takeover --stdin --json
  ```

- **[dns_records.py](dns_records.py)** — full DNS record dump
  (A/AAAA/NS/MX/TXT/SOA/CNAME/CAA via privacy-first DoH) plus a zone-transfer
  (AXFR) attempt against each authoritative nameserver. Flags an open AXFR as a
  finding. Read-only. (AXFR needs outbound TCP:53 — blocked on some hosts/firewalls.)

  ```bash
  python -m recon.dns_records example.com
  python -m recon.dns_records example.com --no-axfr --json
  ```

- **[http_probe.py](http_probe.py)** — probe hosts over HTTP(S), one compact line
  per live host: status, page title, server, redirect target, content length,
  tech guess. The triage step after enumeration. Pass a host, a list
  (`--hosts`/`--stdin`), or a domain with `--enum` to enumerate + probe in one go.

  ```bash
  python -m recon.http_probe example.com --enum
  python -m recon.http_probe --hosts hosts.txt --json
  ```

- **[asn.py](asn.py)** — map an IP/domain/ASN to its autonomous system and every
  announced netblock (via RIPEstat, no-auth). Expands one host into an org's routed
  address space.

  ```bash
  python -m recon.asn example.com
  python -m recon.asn AS13335 --json
  ```

- **[favicon.py](favicon.py)** — compute a site's favicon hash (Shodan's mmh3,
  implemented in pure Python) and emit Shodan/FOFA/ZoomEye pivots to find hosts
  sharing it (e.g. a CDN-hidden origin).

  ```bash
  python -m recon.favicon https://example.com
  ```

- **[secrets_scan.py](secrets_scan.py)** — scan a file/dir tree for leaked secrets
  (API keys, tokens, private keys) as `file:line`. Shares the ruleset with
  [../web/js_recon.py](../web/js_recon.py).

  ```bash
  python -m recon.secrets_scan ./src --json
  ```
