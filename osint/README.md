# osint

Person-centric OSINT: resolve one seed — a name, a handle, an email — into the
accounts, career, education, records and web presence attached to it.

Everything here is **passive**: public pages, public APIs, DNS. Nothing logs in,
nothing writes, nothing contacts the subject.

## Design rules specific to this folder

1. **Many sources per question, never one.** Every capability has fallbacks: 12
   search engines, 5 breach sources, 3 identity sources per address, 7 public
   registers. One dead API degrades the answer; it never fails the run. Sources
   that returned nothing are reported separately from sources that broke.
2. **False positives are the enemy.** Half the sites on the internet return HTTP
   200 for a profile that doesn't exist. `username.py` probes a random control
   handle on every site in the same run and quarantines any site that "finds"
   it. A hit you can't trust is worse than no hit.
3. **Say what is evidence and what is a guess.** Self-declared links (`rel=me`,
   verified Gravatar accounts, Wikidata handles) are the only real proof in
   OSINT and are labelled CONFIRMED. A matching username alone is MEDIUM at
   best, and the output says so, every time.
4. **Every stage's raw output is returned.** The operator — human or model — is
   better than any heuristic at noticing a wrong "John Smith" or a handle that
   needs a suffix dropped. Read the intermediate results, change one input,
   re-run one stage.
5. **The operator does the thinking that needs thinking.** Decomposing
   `caganefecalidag` into `cagan efe calidag` is obvious to a person or an LLM
   and hopeless for a heuristic, so this package doesn't try — you supply the
   name parts, it does the exhaustive mechanical expansion.

## Tools

- **[person.py](person.py)** — the orchestrator. Runs every stage below in
  dependency order, then correlates and scores everything found. Start here.

  ```bash
  python -m osint.person --name "Ada Lovelace" --employer "Analytical Engines"
  python -m osint.person --name "Cagan Calidag" --region TR --result-table
  python -m osint.person --handle torvalds --stages username,profile,correlate
  ```

  Two things happen automatically inside it:

  **Name refinement.** You search `cagan calidag`; Instagram's profile metadata
  says `Çağan Efe Çalıdağ`. Diacritics and middle names are matched across
  spellings, the seed is rewritten, and the handle sweep re-runs against the
  corrected name immediately — before the remaining stages continue. Search
  result titles are used as a fallback when a platform is rate-limiting.

  **Recursive expansion.** Personal sites and link-in-bio pages name accounts no
  sweep would reach, so discovered profile URLs are queued and extracted too.
  Only `rel=me` links and links on *personal* sites are followed — a platform
  profile page's footer links belong to the platform, not the person.

- **[variants.py](variants.py)** — name parts → handle and email candidates,
  ordered so the obvious spellings come first. Offline, instant.

  ```bash
  python -m osint.variants --name "Cagan Efe Calidag"
  python -m osint.variants --name "Ada Lovelace" --email-domain example.com
  ```

- **[username.py](username.py)** — sweep one or many handles across ~70
  platforms with the false-positive control described above.

  ```bash
  python -m osint.username cagancalidag caganefecalidag caganc
  python -m osint.username torvalds --category dev,social
  ```

- **[profile.py](profile.py)** — extract identity from any profile page or
  website: JSON-LD, microformats `rel=me`, OpenGraph, emails, phones, birth
  hints, and every cross-platform account the page links to.

  ```bash
  python -m osint.profile https://github.com/torvalds
  ```

- **[email.py](email.py)** — everything public about an address: Gravatar
  identity (name/bio/location/verified accounts), GitHub commit authorship,
  breach and infostealer exposure, MX and hygiene classification.

  ```bash
  python -m osint.email someone@example.com
  ```

- **[websearch.py](websearch.py)** — 12 search engines in parallel, merged and
  ranked by cross-engine agreement. `--person` runs the social dork set, which
  is the only honest way to cover Instagram/Facebook/Pinterest/Reddit.

  ```bash
  python -m osint.websearch --person "Ada Lovelace" --extra "Istanbul"
  ```

- **[linkedin.py](linkedin.py)** — parse public LinkedIn profiles (full career
  and education history with dates), or find them by name via search engines.

  ```bash
  python -m osint.linkedin williamhgates
  python -m osint.linkedin --discover "Ada Lovelace" --company Acme
  ```

- **[records.py](records.py)** — public registers: Wikidata (date of birth,
  education, employers, declared handles), Wikipedia, SEC EDGAR, GLEIF, plus
  Companies House / OpenCorporates / OpenSanctions when keys are set.

  ```bash
  python -m osint.records "Ada Lovelace"
  ```

- **[vehicle.py](vehicle.py)** — VIN → full specification (NHTSA), plate →
  issuing region and, for the UK, registration date. **No owner lookup** — see
  the boundary section below.

  ```bash
  python -m osint.vehicle --vin 1HGCM82633A004352
  python -m osint.vehicle --plate "34 ABC 123"
  ```

- **[contacts.py](contacts.py)** — phone numbers and postal addresses, validated
  rather than regex-matched: E.164 normalization, the real country calling-code
  table, line-type detection, and a confidence per hit. A national-format number
  is only reported when a phone word sits near it.

  ```bash
  python -m osint.contacts --text "call +90 532 123 45 67" --region TR
  ```

- **[infra.py](infra.py)** — a domain's own graph: RDAP registration, DNS, IPs,
  netblocks, ASN, TLS certificate and SANs, web technology, subdomains. Wraps the
  repo's `recon/` and `web/` tools.

  ```bash
  python -m osint.infra example.com --active
  ```

- **[github.py](github.py)** — a GitHub account's profile fields plus the
  **author email addresses in public commit metadata**. For anyone who writes
  code this is usually the only place a real address is published. Bot/CI
  identities are filtered; the noreply proxy's numeric id is kept as a permanent
  account identifier.

  ```bash
  python -m osint.github MrBiscuitTR
  ```

- **[pdf.py](pdf.py)** — text and contact details out of PDFs (CVs, certificates,
  bios). Three tiers, and it tells you which one ran: `pdftotext` when poppler is
  installed, a stdlib content-stream parser otherwise, and `tesseract` OCR for
  files with no text layer. Kerned `TJ` fragments are joined without spaces, so
  an email survives instead of arriving as four pieces.

  ```bash
  python -m osint.pdf https://example.com/cv.pdf --region TR
  python -m osint.pdf scan.pdf --ocr --lang eng+tur
  ```

- **[fetch.py](fetch.py)** — shared infrastructure: browser-realistic headers
  with UA rotation, redirect chains, cookie jars, anti-bot detection, the
  multi-source `gather()` fan-out, and an optional Playwright renderer.

## The typical loop

The tools are built to be re-run with changed inputs, not run once:

```
variants --name "Cagan Efe Calidag"     -> 37 handle candidates
username <top 8 of those>               -> 3 hits
profile <each hit URL>                  -> real name "Çağan Çalıdağ", a city, a rel=me link
variants --name "Çağan Çalıdağ"         -> corrected candidates
username <those>                        -> 5 more hits
websearch --person <name> --extra <city> -> the login-walled platforms
```

`person.py` automates this loop, but each step remains individually callable so
you can intervene at any point.

## Entity coverage

The Maltego-style entity classes this package can actually produce, and where
each comes from:

| Entity | Source |
| --- | --- |
| Person, alias, alternate spelling | profile/username metadata, Wikidata, LinkedIn |
| Email address | GitHub commit metadata, Gravatar, `mailto:` links, Cloudflare-obfuscated addresses, contact-page crawl, PDFs, permutation |
| Phone number | `tel:` links, page text and PDFs — E.164-validated with a confidence |
| Physical address | JSON-LD `PostalAddress`, microformats, free text |
| Location | profile metadata, LinkedIn, Gravatar |
| Social profile / handle / ID | ~70 platforms incl. Instagram, X, Facebook, TikTok |
| Date of birth | Wikidata; page-text hints marked unverified |
| Employer, education, occupation | LinkedIn JSON-LD, Wikidata |
| Interests | JSON-LD `knowsAbout`, keywords, topic tags |
| Breach / leak | XposedOrNot, HIBP, LeakCheck, Hudson Rock (infostealers) |
| Company registration | Companies House, GLEIF, SEC EDGAR |
| Parent / subsidiary | GLEIF relationship records |
| Executives / officers | Companies House, OpenCorporates |
| Sanctions / PEP | OpenSanctions |
| Domain, registrar, dates | RDAP |
| IP, netblock, ASN | DNS + RIPEstat |
| DNS records | privacy-first DoH |
| TLS certificate, SANs | `web/tls_audit.py` |
| Website technology | `recon/http_probe.py` |
| Vehicle (VIN, plate region) | NHTSA vPIC, built-in plate tables |

`--result-table` prints all of it as one aligned table.

Not achievable and deliberately absent: plate-to-owner, credit files, voter
rolls, paid people-search brokers, and anything behind a login.

## Configuration

Everything works with **no keys at all**. Optional keys unlock extra sources:

| Env var | Unlocks |
| --- | --- |
| `SEARX_URL` | Your own SearXNG instance (best single upgrade — see below) |
| `BRAVE_API_KEY` / `SERPER_API_KEY` / `GOOGLE_CSE_KEY`+`GOOGLE_CSE_CX` | Keyed search engines |
| `GITHUB_TOKEN` | Reliable GitHub commit-email search (unauthenticated is throttled) |
| `HIBP_API_KEY` / `RAPIDAPI_KEY` | HaveIBeenPwned, BreachDirectory |
| `COMPANIES_HOUSE_KEY` / `OPENCORPORATES_API_KEY` / `OPENSANCTIONS_API_KEY` | Company officers, sanctions/PEP screening |
| `DVLA_API_KEY` | UK vehicle data by plate (no owner data) |
| `SEC_CONTACT` | Your contact string for the SEC's required User-Agent |

### SearXNG is the highest-value source here

A SearXNG instance is itself a meta-engine: one query fans out to Google, Bing,
Brave, Wikipedia and dozens more, with no API keys and no per-engine quotas.
`websearch.py` uses it first when configured.

Public instances are tried automatically (they rate-limit hard and mostly
disable the JSON API, so several are attempted in random order). Pointing at
your own instance removes all of that:

```bash
export SEARX_URL=http://localhost:8080          # single instance
export SEARX_URL=http://localhost:8080,https://opnxng.com   # with a fallback
```

If you run your own, enable the JSON API in `settings.yml` — it is faster and
more reliable than HTML parsing:

```yaml
search:
  formats:
    - html
    - json
```

### Setting an env var permanently on Windows 11

Set it once for your user account (persists across reboots and terminals):

```powershell
# PowerShell — permanent, current user. Reopen the terminal afterwards.
[Environment]::SetEnvironmentVariable('SEARX_URL', 'http://localhost:8080', 'User')

# check it
[Environment]::GetEnvironmentVariable('SEARX_URL', 'User')
```

Equivalent in `cmd.exe`: `setx SEARX_URL "http://localhost:8080"` (also
permanent; note `setx` does **not** affect the current window).

For the GUI: press `Win`, type "environment variables", open *Edit the system
environment variables* → *Environment Variables…* → under *User variables* click
*New*.

Important details:

- **A new value is only visible to newly started processes.** Restart your
  terminal — and VS Code entirely, not just its integrated terminal, since it
  passes its own environment to child processes.
- For one session only, use `$env:SEARX_URL = 'http://localhost:8080'` in
  PowerShell or `export SEARX_URL=...` in Git Bash — that is what these tools
  read either way, since Python sees the process environment regardless of which
  shell set it.
- Git Bash inherits Windows user variables, so setting it once via PowerShell
  covers both shells.

## Scope and the legal boundary

This aggregates information that is already public. That is what a background
check, a due-diligence report, or the recon phase of an authorized red team
already does. Aggregation is nevertheless exactly what data-protection law
regulates (GDPR, UK GDPR, KVKK, CCPA) — so have a legitimate basis before
running any of this against a person who is not you or your client, and keep the
output out of commits (see [../docs/scope.md](../docs/scope.md)).

**What this folder deliberately does not do**, and why:

- **Licence plate → owner.** Vehicle registration records are protected
  personal data: the DPPA (18 U.S.C. 2721) in the US, GDPR in the EU/UK, KVKK in
  Turkey. There is no lawful public API. `vehicle.py` decodes the region and
  registration date, and tells you the actual lawful routes (DMV request under a
  permissible use, DVLA V888, subpoena) instead of pretending otherwise.
- **Paid people-search brokers, credit files, voter rolls.** Out of scope.
  `records.py` queries registers published *for public inspection*.
- **SMTP `VRFY`/`RCPT TO` probing** to test whether an address exists. It is
  unreliable against catch-all and greylisting domains, rude to the receiving
  server, and gets source IPs blacklisted.
- **Anything behind a login.** No session cookies, no credential use, no
  scraping of authenticated apps. Login-walled platforms are reported as
  `manual` with a URL for a human to open, or reached through their indexed
  public profiles via search engines.
- **Passwords from breach data.** Breach sources here return metadata — which
  corpus, which field types — never credentials.
