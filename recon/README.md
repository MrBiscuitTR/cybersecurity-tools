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
