"""Operator guidance for the osint tools, surfaced as MCP tool descriptions.

Split out of :mod:`mcp_server.guides` because person-centric OSINT needs more
teaching than the other domains: the tools are meant to be run in a LOOP with the
operator's judgement in the middle, and confidence has to be reported honestly or
the output actively misleads. Same contract as ``guides.py`` — one constant per
tool, kept in sync with the tool itself.
"""

WORKFLOW = """\
HOW THE osint TOOLS FIT TOGETHER (read this before using any of them)

These tools are built for a LOOP, not a single call. The first sweep is never the
best one — it gets you a real name or a corrected handle, and THAT is what makes
the second sweep productive. Budget for two or three passes.

  1. osint_variants   name -> handle/email candidates (offline, instant, free)
  2. osint_username   sweep the candidates you believe in across ~70 platforms
  3. osint_profile    each hit -> real name, bio, location, employer, LINKED ACCOUNTS
  4. back to step 1   with the corrected name/spelling you just learned
  5. osint_websearch  anything the sweep can't reach, and a metadata fallback
                      when a platform rate-limits you
  6. osint_email      any address found -> Gravatar identity, breaches, git commits
  7. osint_linkedin   career + education history from the public profile
  8. osint_records    Wikidata/registries -> date of birth, education, employers
  9. osint_person     runs all of the above and scores what it found

YOUR JOB VERSUS THE TOOLS' JOB
  The tools do exhaustive mechanical work. YOU do the reading comprehension:
  - Decompose run-together handles yourself. "caganefecalidag" is obviously
    "Cagan Efe Calidag" to you and unguessable for a heuristic. Pass the parts to
    osint_variants as `name` — it deliberately does NOT guess splits.
  - Recognize when a hit is a DIFFERENT person with the same handle. Check the
    bio, city and photo before merging identities.
  - Notice suffixes/prefixes worth stripping or adding (dev, official, 07, xX_).
    Pass edited handle lists back to osint_username — it takes MANY handles.
  - Decide when a name is too common to search without a disambiguator, and pass
    employer/city as `extra`.

CONFIDENCE — never overstate what you have
  CONFIRMED  the person's own profile links to it (rel=me, verified Gravatar
             account, Wikidata handle). This is the ONLY real proof in OSINT.
  HIGH       several independent signals agree (name + location + handle)
  MEDIUM     one solid signal — an exact handle match, or a name match
  LOW        the handle exists and nothing else ties it to your target. Very
             often a different person. Say so when you report it.

Report findings with their confidence attached. "torvalds on GitHub, Codeberg and
Kaggle (MEDIUM — same handle, no cross-confirmation)" is a useful answer;
"I found their Kaggle" is not.

SCOPE
  Everything is passive and public — no logins, no writes, no contact with the
  subject. Aggregating public data about a person is still regulated (GDPR/KVKK/
  CCPA): expect a legitimate purpose. Licence-plate-to-owner is not available at
  any price and osint_vehicle will tell you the lawful routes instead.
"""

VARIANTS = """\
Expand known name parts into the handles and email addresses a person plausibly
uses. Pure computation — no network, instant, free. Call it as often as you like.

WHEN TO USE
  Before every username sweep, and AGAIN every time you learn a better spelling
  of the name (from a profile, a Gravatar, a LinkedIn page).

INPUT
  name: full name as written. Accents and Turkish letters are folded correctly
    ("Cagan Efe Calidag" with Turkish spelling -> cagan/efe/calidag).
  handle: a handle to NORMALIZE (strip xX_/real/dev decoration and digit
    suffixes). It does not guess name splits — that part is your job.
  email_domain: with `name`, also generates corporate address permutations.

OUTPUT
  handles: ordered candidates, MOST OBVIOUS FIRST. Full spellings
    (cagancalidag, caganefecalidag) come before abbreviations (ccalidag, caganc)
    before truncations (cagancal). Sweep the top 5-15, not all of them.
  emails: hypotheses only — nothing is verified.
  normalized: {core, removed, digits}. Digits are often a birth year: a lead for
    a DoB, never a fact.

WHAT TO DO NEXT
  Hand an EDITED list to osint_username. Drop candidates that look wrong, add any
  you know. That editing step is where you add value over a brute-force sweep.
"""

USERNAME = """\
Check one or many handles across ~70 platforms and report where each exists.

THE THING THAT MAKES THIS DIFFERENT
  Many sites return HTTP 200 for profiles that don't exist (bot walls, SPAs,
  soft-404s), so naive checkers report accounts that aren't there. This probes a
  RANDOM CONTROL handle against every site in the same run; any site that
  "finds" the control is marked UNRELIABLE and its hit is quarantined. Trust the
  FOUND list; ignore the UNRELIABLE list entirely.

INPUT
  username: ONE handle or a LIST. Pass the whole candidate set at once — you get
    a side-by-side comparison, and a handle found on 6 sites is a much better
    lead than one found on 1.
  category: dev/social/pro/creative/blog/gaming/commerce to narrow the sweep.

THE BIG SOCIAL PLATFORMS ARE CHECKED, NOT SKIPPED
  Instagram, X, Facebook, Threads, TikTok, Twitch, Pinterest, Snapchat and
  Medium serve OpenGraph metadata for public profiles to unauthenticated
  requests, and omit it for handles that don't exist. So they are verified
  properly — and the DISPLAY NAME, BIO and FOLLOWER COUNTS come back with the
  verdict. Instagram serves that metadata even for PRIVATE accounts: name, bio
  and counts are public; only the posts are not.
  The display name is often a fuller spelling than your seed ("cagan calidag" ->
  "Çağan Efe Çalıdağ"). When you get one, feed it straight back into
  osint_variants and re-sweep — that is the highest-yield move available.

OUTPUT — five states, and the difference matters
  FOUND       exists, on a site proven to reject the control handle. May carry
              profile_name / bio / stats.
  UNRELIABLE  the site says yes to everything — a hit here means NOTHING
  UNKNOWN     blocked (403/429), errored, or the platform served its generic
              page. NOT the same as absent. The generic-page case is genuinely
              ambiguous (no such handle OR you are being rate-limited), so it is
              never reported as absent — open the URL to settle it.
  MANUAL      genuinely uncheckable (no addressable profile URL, or a bot wall on
              every request). The URL is emitted, never a guess.
  absent      counted per handle, not listed individually

RATE LIMITING
  Handles are checked one at a time per site (parallel ACROSS sites) precisely
  because firing nine simultaneous requests at Instagram makes it serve the
  generic page to everything. If you still get many UNKNOWNs, sweep fewer
  handles or wait.

WHAT TO DO NEXT
  - Run osint_profile on every FOUND url. That is where the actual identity data
    is, and where you find links to accounts the sweep couldn't reach.
  - Cover MANUAL/UNKNOWN platforms with osint_websearch: a search result title
    ("Full Name (@handle) • Instagram") carries the same metadata and keeps
    working when the platform itself is rate-limiting you.
  - A hit does NOT prove it's your person. Confirm with the bio before claiming.

FAILURE / RETRY
  Sites rate-limit; UNKNOWN counts vary between runs. Re-running is cheap and the
  mix changes. If EVERY site is unknown, the network is blocking you.
"""

PROFILE = """\
Extract identity data from any public profile page or website.

This is the step that converts "the account exists" into facts: name, bio,
location, employer, education, dates, emails, phones — and every other account
the page links to.

WHY THE LINKS MATTER MOST
  A guessed connection between two accounts is a hypothesis. A link the person
  PUT on their own profile is evidence. rel=me links and schema.org sameAs are
  reported separately as SELF-DECLARED for exactly that reason — treat those as
  the same person unless something contradicts it.

INPUT
  url: any profile or personal site. LinkedIn public profiles work (see
    osint_linkedin for a dedicated parser). render=true uses a headless browser
    for JS-only pages, but only if Playwright is installed — it is optional and
    almost never needed.

OUTPUT
  identity (name/headline/locality/country/employers/education/birth_date),
  rel_me (self-declared accounts), links (other accounts referenced),
  emails (including "name [at] host [dot] com" obfuscation), phones (noisy —
  verify), birth_hints (only dates a birth word introduced).

WHAT TO DO NEXT
  - Feed a recovered REAL NAME back into osint_variants and re-sweep. This single
    round trip finds more accounts than anything else you can do.
  - Run osint_profile on the linked profiles to widen the graph.
  - Feed discovered emails to osint_email.

FAILURE / RETRY
  blocked=true means an anti-bot page, not an empty profile — retry or open it
  yourself. Empty identity on a JS-heavy site is normal; try render=true.
"""

EMAIL = """\
Everything publicly knowable about an email address, from ~10 sources at once.

An address is the strongest pivot in OSINT: globally unique, reused for years,
and it links accounts that share nothing else.

OUTPUT — read it in this order
  identity   names, usernames, location, bio, and LINKED ACCOUNTS from the
             Gravatar profile. Accounts marked verified were attached by the
             owner: treat them as CONFIRMED. This is the richest free source
             that exists for an address — it often hands you the real name plus
             their X, LinkedIn, GitHub and Instagram in one call.
  breaches   which corpora the address appears in. The breach NAMES are
             intelligence in themselves: each one is a service they used and a
             platform worth checking for a profile.
  hudsonrock infostealer-infection data — different from a breach: it means a
             machine they used was compromised.
  classification  role_account (info@/admin@ — not a person, pivot to the org),
             disposable (throwaway domain, expect a thin footprint), plus_tag
             (ada+github@ tells you where they used it).

WHAT IT WILL NOT DO
  No SMTP probing to test whether an address exists — unreliable against
  catch-all domains and it gets IPs blacklisted. Existence is inferred from
  evidence. No passwords are retrieved, only breach metadata.

WHAT TO DO NEXT
  - A recovered real name -> osint_variants -> osint_username.
  - Verified linked accounts -> osint_profile on each.
  - The local part is itself a handle candidate: sweep it.

FAILURE / RETRY
  Sources needing keys (HIBP, BreachDirectory) are listed as unavailable when the
  env var is missing — that is expected, not an error. "nothing found by" means
  the source answered and had nothing, which is a real (negative) result.
"""

WEBSEARCH = """\
Query four keyless engines in parallel and merge the results by agreement.

WHEN TO USE
  - To cover the login-walled platforms (Instagram, Facebook, Pinterest, Reddit,
    TikTok, X). Their profiles ARE indexed even though direct probing fails —
    this is the only honest way to find them.
  - To find anything a username sweep can't: articles, CVs, conference bios,
    court documents, company pages.

INPUT
  query: a raw query. Full operator support — site:, quotes, OR.
  person + handle + extra: dork mode. `extra` (employer, city, university) is
    what turns 10,000 "John Smith" hits into 5 — always pass it for a common name.
  kinds: which dork groups to run —
    identity    the name alone, plus bio/profile/about
    contact     email/phone wording and "@gmail.com"-style literals. The point
                is the SNIPPET: engines print the address next to the name, so
                `contacts` in the result often has it without fetching anything.
    documents   filetype:pdf/doc CVs — where phone numbers and addresses live
    academic    site:edu / university / researcher wording, for staff and
                student pages, which publish institutional addresses
  Use site_dorks() to mine a domain once it is known to be relevant.

OUTPUT
  results ranked by `agreement` = how many engines returned that URL. A URL found
  by 4 engines is real; a single-engine hit is often a stale index entry.
  by_platform groups the social profiles found.
  engines_used / engines_down — expect 3-6 up out of 8 keyless engines. That is
  normal, not a malfunction; it is why there are many.

WHAT TO DO NEXT
  Run osint_profile on promising URLs. Re-run with a tighter `extra` if the name
  is common.

FAILURE / RETRY
  Engines rate-limit constantly — retry once before concluding something isn't
  there. `searx_unresponsive` names the upstreams that failed inside SearXNG:
  "3 results" usually means Brave and DuckDuckGo were captcha'd, NOT that the
  person has no footprint. Say that rather than reporting an empty finding.
  A SearXNG instance ($SEARX_URL) is by far the best upgrade — it is a
  meta-engine and the only free route to Google. Enable `google` and `bing` in
  its settings; a stock instance often has only `google cse`, which is limited
  to a handful of results.
"""

LINKEDIN = """\
Read public LinkedIn profiles: full career and education history with dates.

Public profiles embed a schema.org Person block containing employers with
start/end dates, schools with dates, job titles, city, country and headline. This
parses it. It is the densest career data available anywhere for most people.

TWO MODES
  target:   a vanity name or profile URL -> parse that profile
  discover: a NAME (+ company/location) -> find profile URLs via search engines.
            Use this first when you don't have the URL; it also works when
            LinkedIn is rate-limiting, and the result SNIPPET usually contains
            the headline and employer even for profiles that would authwall.

READING THE RESULT — two failure modes you must not confuse
  authwall=true   the profile isn't public, or LinkedIn challenged the request.
  http_status=999 LinkedIn's rate-limit/deny code. It means "ask later". It does
                  NOT mean the profile is absent — never report it as such.

LIMITS
  Public profiles only. Connections and contact info are behind a login and are
  not attempted: no session cookies, no credentials. Keep volume low and prefer
  discover (which asks search engines, not LinkedIn).

WHAT TO DO NEXT
  Employers give you corporate mail domains -> osint_variants with email_domain.
  The city is a strong disambiguator -> pass it as `extra` to osint_websearch.
"""

RECORDS = """\
Search public registers for a person or company: Wikidata, Wikipedia, SEC EDGAR,
GLEIF, plus Companies House / OpenCorporates / OpenSanctions when keys are set.

WHEN TO USE
  For structured FACTS rather than mentions: date of birth, birthplace,
  citizenship, education, employers, directorships, corporate addresses,
  sanctions/PEP status.

READ THIS BEFORE INTERPRETING AN EMPTY RESULT
  These registers cover notable people, company officers and securities filers.
  A private individual is simply NOT IN THEM, and an empty result is the normal,
  correct answer for most people — it is not a tool failure. Use osint_websearch
  and osint_username for ordinary people.

OUTPUT
  Wikidata is the highlight: birth_date, educated_at, employer, occupation, and
  the person's own declared social handles (which are self-declared, so treat
  accounts found that way as CONFIRMED).
  wikidata_candidates lists other entities that matched — CHECK IT. Picking the
  wrong "John Smith" from Wikidata is the classic error here.

WHAT TO DO NEXT
  Declared handles -> osint_username / osint_profile. Education and employers ->
  disambiguators for osint_websearch. Officer records give an address and often
  a partial DoB — cross-check it against other findings.
"""

VEHICLE = """\
Decode a VIN to a full vehicle specification, or a licence plate to its issuing
region and (UK) registration date.

VIN     NHTSA's free database returns make, model, year, plant, engine, body and
        restraints. The check digit is validated locally first, so typos are
        caught before a request goes out. The model-year code repeats on a
        30-year cycle, so two candidate years are reported when both are
        plausible — the decoded data settles it.
PLATE   Turkey: leading two digits = province (34 = Istanbul), which is a strong
        geographic disambiguator for a name search.
        UK: area code + age identifier = the exact half-year of first
        registration, plus the DVLA region.
        Germany: 1-3 letter district prefix.
        US: plates are NOT self-describing; the state cannot be derived.

PLATE -> OWNER IS NOT AVAILABLE. Not through this tool and not through any
lawful public API. Those records are protected personal data: DPPA
(18 U.S.C. 2721) in the US, GDPR in the EU/UK, KVKK in Turkey. If asked, say so
and relay the lawful routes the tool returns (DMV request under a permissible
use, DVLA V888, police report, subpoena). Sites advertising instant plate lookup
sell scraped or fabricated data. Do not substitute one.
"""

PERSON = """\
The orchestrator: runs every osint tool on one person and correlates the results.

INPUT — give it whatever you have
  name, handles (list), emails (list), email_domain, location, employer. More
  seeds = far better results; location/employer especially, because they
  disambiguate common names and feed the confidence scoring.

STAGES — and why you should often run only some
  seed, username, email, search, linkedin, records, profile, correlate.
  Pass a subset to iterate cheaply. After a first full run you will usually
  re-run just `username,profile,correlate` with a corrected name or an edited
  handle list, which is much faster than repeating everything.

OUTPUT
  EVERY stage's raw output is returned alongside the correlated view — read the
  stage output, not just the summary. `accounts` is grouped by confidence with
  the EVIDENCE for each one spelled out; `identity` merges names, locations,
  employers, education and emails with the sources that claimed each value.

HOW TO REPORT IT
  Lead with CONFIRMED and HIGH. State LOW-confidence hits as what they are:
  "the handle exists on X, but nothing links it to this person." Never collapse
  the confidence levels into a flat list of "their accounts" — that is how OSINT
  reports get people wrong.

WHAT TO DO NEXT
  Follow `next_steps` in the result. Usually: a better name spelling was found,
  so re-run the seed and username stages with it.
"""

CONTACTS = """\
Extract and validate phone numbers and postal addresses from text or HTML.

Phone extraction is a false-positive problem, not a matching problem: any regex
loose enough to catch a real number also catches order ids, timestamps, prices
and version strings. So every candidate here is normalized, length-checked
against E.164, matched against the real country calling-code table, screened for
non-phone shapes, and scored by the words around it.

INPUT
  text / file: what to scan (HTML is reduced to text automatically).
  region: ISO code (TR, GB, US...) for numbers written WITHOUT a country code.
    A national-format number is only reported when a phone word ("tel",
    "mobile", "whatsapp") sits near it — a bare 10-digit run is an id or a price
    far more often than a phone number, so it is dropped rather than guessed.

OUTPUT
  phones: E.164 form, country, line type where derivable (Turkish 5xx and UK 7xx
    are mobile), confidence, and the surrounding text so you can check it.
  addresses: structured JSON-LD PostalAddress and microformats first (high
    confidence), then free-text matches that needed BOTH a street phrase and a
    nearby postcode. A bare 5-digit postcode fits the US, Turkey, Germany and
    France, so the country is reported as ambiguous rather than guessed.

HOW TO REPORT IT
  Quote the confidence. A "medium" national-format number is a lead to verify,
  not a fact. Never present an ambiguous postcode country as settled.
"""

INFRA = """\
Infrastructure entities for a domain: RDAP registration, DNS, IPs, netblocks,
ASN, TLS certificate, web technology, subdomains.

WHEN TO USE
  Whenever a domain turns up — the subject's personal site, an employer's mail
  domain, a domain from a certificate. The domain is its own entity with its own
  graph, and it often names the legal organization behind a person.

WHAT COMES BACK
  RDAP: registrar, creation/expiry dates, status. Registrant name and address
    are redacted for most TLDs post-GDPR — that is normal, not a failure; the
    registrar and creation date are still good pivots.
  DNS/IPs/ASN: the netblock and autonomous system that own the address, via
    RIPEstat. Cloudflare/Fastly ASNs mean you are seeing a CDN, not the origin.
  TLS: certificate subject and SANs. SANs name further domains, and the
    organization field (on OV/EV certs) names a legal entity for osint.records.
  related_domains: from cert SANs and MX hosts — each is another infra target.

ACTIVE VS PASSIVE
  Passive by default (DNS, RDAP, third-party APIs only). active=true also
  connects to the host for HTTP fingerprinting and the TLS handshake — ordinary
  browser-shaped requests, but still traffic to the target, so only use it on
  infrastructure the operator is authorized to touch.
"""

GITHUB = """Everything GitHub publishes about an account, including the author's real email.

WHY THIS MATTERS MORE THAN THE PROFILE PAGE
  Every public commit stores the author's configured email in its metadata, and
  the API hands it to anyone. A developer who has never written their address on
  any page has usually pushed it to a public repo hundreds of times. This is the
  single most reliable way to get a real address for a technical person.

OUTPUT
  profile   name, bio, company, location, blog, X handle, join date — the API
            returns a dozen fields the HTML page never shows together. `company`
            and `location` are strong disambiguators for search.
  emails    two kinds, and they are NOT equivalent:
              real      an actual mailbox -> feed it to osint_email
              noreply   ID+login@users.noreply.github.com — a privacy proxy, not
                        reachable. The NUMBER is still valuable: it is a
                        permanent account id that survives username changes.
            Bot/CI identities (dependabot, vercel, github-actions) are filtered.
  orgs / topics / repos — what they actually work on.

RATE LIMITS
  60 requests/hour unauthenticated, which runs out fast. $GITHUB_TOKEN raises it
  to 5000/hour and is the single most useful key for this whole package.

WHAT TO DO NEXT
  Real address -> osint_email (Gravatar identity, breaches, other accounts).
  blog field -> osint_profile then osint_infra on the domain.
  company -> osint_records and as `extra` for osint_websearch.
"""

PDF = """Extract text and contact details from a PDF — CVs, certificates, bios, scans.

WHY IT MATTERS
  A CV is usually the only document where somebody publishes a phone number or a
  postal address, and CVs are PDFs. Pages linked from a personal site are worth
  opening for exactly this reason.

THREE TIERS, and the result says which one produced the text
  pdftotext  poppler-utils, if installed. Best: resolves font encodings and
             ToUnicode CMaps, so unusual fonts come out as real characters.
  builtin    a stdlib parser. No dependencies. Good on ordinary text PDFs.
  ocr        tesseract, if installed and `ocr` is set. The ONLY way to read a
             PDF with no text layer.

READING THE RESULT
  has_text_layer=false means the file is a scan or an exported image. That is
  not a tool failure and not an empty document — the text is in pixels. Say so,
  and suggest OCR rather than reporting "no contact details found".
  method=ocr means the text came from image recognition: expect character
  errors, and verify anything you act on (a digit in a phone number especially).

INPUT
  source: a file path or an http(s) URL.
  ocr: allow the OCR tier. lang: tesseract languages, e.g. "eng+tur".
  region: ISO code so national-format phone numbers can be read.
"""
