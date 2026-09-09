"""Full person investigation: run every osint tool, correlate, and score it.

The orchestrator. Give it whatever you have — a name, a handle, an email, an
employer — and it runs the whole package in dependency order, feeds each stage's
output into the next, and scores every entity it found by how strongly the
evidence ties it to your target.

Stages (each independently runnable with ``--stages``):

    seed      expand the name into handle and email candidates (osint.variants)
    username  sweep the handle candidates across ~70 platforms (osint.username)
    email     enrich every known/derived address (osint.email)
    search    multi-engine dorks incl. every major social platform (osint.websearch)
    linkedin  find and parse the public LinkedIn profile (osint.linkedin)
    records   Wikidata / SEC / registries / sanctions / corporate ownership
    profile   extract identity data from every URL found above (osint.profile)
    infra     domains found -> RDAP, DNS, IPs, netblocks, ASN, TLS, tech
    correlate score and merge everything into one identity picture

TWO THINGS HAPPEN AUTOMATICALLY INSIDE THE PROFILE STAGE, because they are what
actually finds people:

  Name refinement. The seed name is usually a transliteration or a short form —
  you search "cagan calidag" and a profile says "Çağan Efe Çalıdağ". When a
  fuller or better-spelled version of the SAME name turns up, the seed is
  rewritten and the handle sweep re-runs against it immediately, before anything
  else continues. Diacritics and middle names are matched across spellings
  (see :func:`osint.variants.name_matches`), so the two forms are recognized as
  one person rather than two.

  Recursive expansion. Personal sites and link-in-bio pages are hubs: one page
  can name six accounts that no username sweep would ever reach. Any profile URL
  discovered while extracting is queued and extracted too, to a bounded depth.

Confidence is evidence-based and always explained:

    CONFIRMED  the target's own profile links to it (rel=me, a verified Gravatar
               account, or a handle declared on Wikidata)
    HIGH       several independent signals agree (name + location + handle)
    MEDIUM     one solid signal (exact handle match, or a name match)
    LOW        the handle exists but nothing ties it to your target — a
               different person may simply have the same username

Same-handle-different-person is the default failure mode of username OSINT, and
the scoring keeps it visible rather than papering over it.

Safety: read-only throughout. Every underlying tool is passive — public pages,
public APIs, DNS. No logins, no writes, no contact with the subject. The infra
stage stays passive unless ``--active-infra`` is given.

Legal note: this aggregates public information about a person. Aggregation is
what data-protection law (GDPR, KVKK, CCPA) regulates, so have a legitimate
basis before running it on someone who isn't you or your client.

Usage:
    python -m osint.person --name "Ada Lovelace"
    python -m osint.person --handle torvalds --result-table
    python -m osint.person --name "Ada Lovelace" --email ada@example.com \
        --employer "Analytical Engines" --location London --region GB
    python -m osint.person --handle torvalds --stages username,profile,correlate
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse as up

from common.output import emit, log
from osint import fetch, variants

STAGES = ("seed", "username", "email", "search", "sites", "linkedin", "records",
          "profile", "github", "infra", "correlate")

# Hosts that are platforms rather than somebody's own site. Derived from the
# username platform table instead of hand-maintained: a hardcoded list silently
# drifts, and a missed host means the infra stage profiles twitch.tv as if it
# were the subject's personal domain.
_EXTRA_HOSTS = frozenset("""
wikipedia.org wikidata.org wikimedia.org google.com bing.com yahoo.com
duckduckgo.com brave.com startpage.com mojeek.com marginalia.nu amazon.com
apple.com microsoft.com cloudflare.com archive.org twitter.com fb.com
threads.com youtu.be goo.gl bit.ly t.co linktr.ee
""".split())


def _known_hosts() -> frozenset[str]:
    """Registrable hosts of every platform we know about."""
    from osint import username as _u
    hosts = set(_EXTRA_HOSTS)
    for site in _u.SITES:
        # Strip the handle only for templates where it IS the subdomain
        # ("https://{u}.tumblr.com"). Substituting first and then removing a
        # leading "x." turns the literal host "x.com" into "com", after which
        # every .com domain on earth counts as a platform.
        template = site.url
        subdomain_templated = template.startswith(("https://{u}.", "http://{u}."))
        host = up.urlparse(template.replace("{u}", "handle")).netloc.lower()
        host = host.removeprefix("www.")
        if subdomain_templated:
            host = host.split(".", 1)[1] if "." in host else host
        if host and "." in host:
            hosts.add(host)
    return frozenset(hosts)


_KNOWN_HOSTS = _known_hosts()


def _is_platform_host(host: str) -> bool:
    """True if ``host`` belongs to a known platform (including subdomains)."""
    host = (host or "").lower().removeprefix("www.")
    return any(host == p or host.endswith("." + p) for p in _KNOWN_HOSTS)


def _norm_name(text: str) -> str:
    return re.sub(r"[^a-z]", "", (text or "").lower())


def _name_tokens(text: str) -> set[str]:
    """Comparable word tokens, ASCII-folded first.

    Without the fold, "Çağan Çalıdağ" splits on every non-ASCII letter and
    produces nothing that matches "cagan calidag" — so the person's own site
    fails to match their own name.
    """
    folded = variants._ascii_fold(text or "").lower()
    return {t for t in re.split(r"[^a-z0-9]+", folded) if len(t) > 2}


def looks_like_a_person_name(value: str, *, min_words: int = 2) -> bool:
    """Reject strings that are page titles rather than names.

    Search result titles ("Cagancalidag cagancalidag.com Çağan Efe Çalıdağ") pass
    a pure token-subset test — they literally contain the real name — so name
    refinement will happily adopt one unless the SHAPE is checked as well.
    """
    value = (value or "").strip()
    if not 3 <= len(value) <= 60:
        return False
    if re.search(r"[·|/#@:]|://|\.\w{2,4}(\s|$)", value):
        return False
    words = value.split()
    return min_words <= len(words) <= 5 and all(w[:1].isalpha() for w in words)


def _plausible_birth(hint: str) -> bool:
    """Drop "birth" dates that are really post or copyright dates.

    Pages date themselves constantly, and a birth word within 40 characters
    of "Sep 5, 2026" is a forum listing, not a date of birth. Nobody whose
    footprint we can search was born in the last few years.
    """
    years = [int(y) for y in re.findall(r"(?:1[89]|20)\d{2}", hint)]
    return bool(years) and all(1800 <= y <= 2015 for y in years)


# Mailbox providers: the domain is the provider's, never the subject's, so
# profiling it yields Google's infrastructure instead of theirs.
FREE_MAIL_DOMAINS = frozenset("""
gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com
ymail.com icloud.com me.com mac.com proton.me protonmail.com pm.me tuta.io
tutanota.com gmx.com gmx.de web.de mail.ru yandex.ru yandex.com zoho.com
aol.com fastmail.com hey.com mail.com inbox.com naver.com qq.com 163.com
""".split())
# Names that never resolve publicly: mDNS/LAN suffixes that turn up in git
# commit metadata ("alierentansug@ali-erens-macbook.local").
_PRIVATE_TLDS = (".local", ".localdomain", ".lan", ".home", ".internal",
                 ".invalid", ".test", ".localhost", ".arpa")


def is_investigable_domain(host: str) -> bool:
    """True if a domain is worth an infra lookup.

    Excludes mailbox providers (you learn about Google, not the person), private
    and reserved suffixes, and anything without a dot.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or "." not in host or " " in host:
        return False
    if host in FREE_MAIL_DOMAINS or host.endswith(_PRIVATE_TLDS):
        return False
    return not _is_platform_host(host)


def _host_of(url: str) -> str:
    try:
        return up.urlparse(url).netloc.lower().removeprefix("www.")
    except ValueError:
        return ""


def _score_account(
    acct: dict,
    *,
    target_name: str,
    handles: set[str],
    emails: set[str],
    location: str,
    employer: str,
    declared_urls: set[str],
) -> tuple[str, int, list[str]]:
    """Score one discovered account against what we know about the target.

    Returns:
        ``(confidence, score, evidence)`` where confidence is
        CONFIRMED/HIGH/MEDIUM/LOW and evidence explains every point awarded.
    """
    score, why = 0, []
    url = (acct.get("url") or "").rstrip("/")
    handle = (acct.get("handle") or acct.get("username") or "").lower()
    profile_name = acct.get("profile_name", "") or ""
    bio = acct.get("bio", "") or ""

    if url in declared_urls:
        score += 60
        why.append("the target's own profile links to this account (self-declared)")
    if acct.get("self_declared"):
        score += 60
        why.append(f"self-declared via {acct.get('declared_by', 'profile link')}")
    if handle and handle in handles:
        score += 20
        why.append(f"handle '{handle}' is one of the target's known/derived handles")
    if profile_name and target_name:
        match = variants.name_matches(profile_name, target_name)
        if match["relation"] == "exact":
            score += 30
            why.append(f"profile name '{profile_name}' matches the target name")
        elif match["match"]:
            score += 22
            why.append(f"profile name '{profile_name}' matches the target "
                       f"({match['relation']}: shares {', '.join(match['shared'])})")
        else:
            score -= 20
            why.append(f"profile name '{profile_name}' does NOT match the target name")
    for addr in emails:
        local = addr.split("@")[0]
        if handle and handle == local.lower():
            score += 15
            why.append(f"handle equals the local part of {addr}")
        if addr.lower() in bio.lower():
            score += 25
            why.append(f"the profile bio contains {addr}")
    if location and bio and _name_tokens(location) & _name_tokens(bio):
        score += 12
        why.append(f"bio mentions the target's location ({location})")
    if employer and bio and _name_tokens(employer) & _name_tokens(bio):
        score += 15
        why.append(f"bio mentions the target's employer ({employer})")
    if acct.get("agreement", 0) >= 3:
        score += 8
        why.append(f"returned by {acct['agreement']} independent search engines")

    if score >= 60:
        conf = "CONFIRMED"
    elif score >= 35:
        conf = "HIGH"
    elif score >= 18:
        conf = "MEDIUM"
    else:
        conf = "LOW"
        why.append("nothing links this to the target beyond the handle itself — "
                   "it may be a different person")
    return conf, score, why


# TLDs a person actually puts a personal site on, cheapest-first.
PERSONAL_TLDS = ("com", "net", "dev", "io", "me", "org", "co", "xyz", "site",
                 "tech", "page", "app", "blog", "info", "fr", "com.tr")


def personal_site_candidates(handles: list[str], name: str = "",
                             *, limit: int = 24) -> list[str]:
    """Domains a person with these handles plausibly owns.

    Search engines are unreliable for finding somebody's own site — it has no
    inbound links and ranks below every scraper that mentions the name. But the
    domain is almost always just the handle plus a common TLD, and checking that
    directly costs one DNS lookup each. ``cagancalidag`` -> ``cagancalidag.com``.

    Args:
        handles: Candidate handles, best first.
        name: Full name, contributing its concatenated form.
        limit: Cap on generated domains.

    Returns:
        Candidate domains, most-likely first, de-duplicated.
    """
    bases: list[str] = []
    for h in handles:
        core = re.sub(r"[^a-z0-9-]", "", h.lower())
        if 3 <= len(core) <= 40 and core not in bases:
            bases.append(core)
    if name:
        joined = re.sub(r"[^a-z0-9]", "", variants._ascii_fold(name).lower())
        if 3 <= len(joined) <= 40 and joined not in bases:
            bases.insert(0, joined)

    out: list[str] = []
    for base in bases[:6]:
        for tld in PERSONAL_TLDS:
            d = f"{base}.{tld}"
            if d not in out:
                out.append(d)
    return out[:limit]


def verify_personal_site(domain: str, *, name: str, handles: list[str],
                         timeout: float = 8.0) -> dict | None:
    """Fetch a candidate domain and decide whether it is really the target's.

    Existence is not enough — parked pages, squatters and unrelated companies
    all answer 200. The page must actually NAME the person (or carry a handle we
    already believe in), which is exactly the "title, description or JSON-LD
    match" test rather than a guess from the domain string.

    Returns:
        ``{"domain","url","matched_on","identity"}`` or None.
    """
    from osint import profile as profile_mod
    r = fetch.get(f"https://{domain}", timeout=timeout, retries=0)
    if not r.ok or r.blocked or len(r.body) < 200:
        return None
    data = profile_mod.extract(r.text, base_url=r.final_url)
    ident = data.get("identity", {}) or {}
    og = data.get("opengraph", {}) or {}

    haystacks = {
        "json-ld name": ident.get("name", ""),
        "page title": data.get("title", ""),
        "og:title": og.get("og:title", ""),
        "meta description": og.get("og:description", "") or og.get("description", ""),
        "meta author": og.get("author", ""),
        "page text": data.get("text_sample", "")[:600],
    }
    want = _name_tokens(name) if name else set()
    for where, hay in haystacks.items():
        if not hay:
            continue
        if want and len(want & _name_tokens(hay)) >= min(2, len(want)):
            return {"domain": domain, "url": r.final_url, "matched_on": where,
                    "identity": ident, "profile": data}
        if any(h.lower() in hay.lower() for h in handles if len(h) > 5):
            return {"domain": domain, "url": r.final_url,
                    "matched_on": f"{where} (handle)", "identity": ident,
                    "profile": data}
    return None


def _extract_batch(urls: list[str], *, timeout: float, region: str,
                   workers: int = 6) -> tuple[list[dict], dict[str, str]]:
    """Run osint.profile over a list of URLs concurrently."""
    from osint import profile as profile_mod
    if not urls:
        return [], {}
    sources = {u: (lambda url=u: profile_mod.run(url, timeout=timeout, region=region))
               for u in urls}
    got, down = fetch.gather(sources, workers=workers, timeout=timeout * 4)
    out = []
    for url, data in got.items():
        out.append({
            "url": url,
            "identity": data.get("identity", {}),
            "rel_me": data.get("rel_me", []),
            "links": data.get("links", []),
            "emails": data.get("emails", []),
            "phones": data.get("phones", []),
            "addresses": data.get("addresses", []),
            "interests": data.get("interests", []),
            "birth_hints": data.get("birth_hints", []),
            "blocked": data.get("blocked", False),
        })
    return out, down


def run(
    *,
    name: str = "",
    handles: list[str] | None = None,
    emails: list[str] | None = None,
    email_domain: str = "",
    location: str = "",
    employer: str = "",
    region: str = "",
    stages: tuple[str, ...] = STAGES,
    max_handles: int = 8,
    max_profiles: int = 12,
    max_queries: int = 6,
    depth: int = 2,
    active_infra: bool = False,
    subdomains: bool = True,
    timeout: float = 20.0,
) -> dict:
    """Run the full investigation and correlate everything found.

    Args:
        name: The target's full name, if known.
        handles: Known handles, combined with any derived from ``name``.
        emails: Known addresses, combined with any derived from ``name`` +
            ``email_domain``.
        email_domain: Employer/personal mail domain for address permutation.
        location: City/country, used to disambiguate and to score.
        employer: Company, used to disambiguate and to score.
        region: ISO country code for reading phone numbers and postcodes.
        stages: Which stages to run, in ``STAGES`` order.
        max_handles: How many derived handle candidates to sweep.
        max_profiles: Cap on URLs fetched per profile round.
        max_queries: Cap on search-engine dork queries.
        depth: Profile expansion rounds. 1 = only the URLs already found;
            2 (default) also extracts profiles discovered on those pages.
        active_infra: Let the infra stage connect to hosts (HTTP/TLS).
        subdomains: Run passive subdomain enumeration for each domain found.
        timeout: Per-request timeout passed to the underlying tools.

    Returns:
        Every stage's raw output plus ``accounts``, ``identity``, ``entities``
        and ``name_refinement``.

    Raises:
        ValueError: If no seed was given, or a stage name is unknown.
    """
    if not (name or handles or emails):
        raise ValueError("give at least one of: --name, --handle, --email")
    if bad := [s for s in stages if s not in STAGES]:
        raise ValueError(f"unknown stage {bad[0]!r}; pick from {', '.join(STAGES)}")

    known_handles = [h.strip().lstrip("@") for h in (handles or []) if h.strip()]
    known_emails = [e.strip().lower() for e in (emails or []) if e.strip()]
    out: dict = {"target": {"name": name, "handles": known_handles,
                            "emails": known_emails, "location": location,
                            "employer": employer, "region": region},
                 "stages_run": [], "seed": {}, "username": {}, "email": {},
                 "search": {}, "sites": [], "linkedin": {}, "records": {},
                 "profiles": [], "github": [],
                 "infra": [], "accounts": [], "identity": {}, "entities": {},
                 "name_refinement": [], "next_steps": []}

    def expand_seed(person_name: str, cap: int) -> list[str]:
        from osint import variants as v
        seed = v.run(name=person_name, email_domain=email_domain)
        out["seed"] = seed
        derived = [h for h in seed["handles"] if h not in known_handles][:cap]
        for e in seed.get("emails", []):
            if e not in known_emails:
                known_emails.append(e)
        return known_handles + derived

    # --- seed ---------------------------------------------------------------
    sweep_handles = list(known_handles)
    if "seed" in stages and name:
        log("[*] stage seed: expanding name into candidates ...")
        sweep_handles = expand_seed(name, max_handles)
        out["stages_run"].append("seed")

    # --- username -----------------------------------------------------------
    def sweep(hs: list[str]) -> dict:
        from osint import username as username_mod
        try:
            return username_mod.run(hs, timeout=timeout)
        except ValueError as exc:
            return {"error": str(exc), "found": [], "usernames": hs}

    def refine_name(candidates: list[tuple[str, str]]) -> bool:
        """Adopt a fuller/better-spelled form of the SAME name and re-sweep.

        ``candidates`` is ``[(name, where_it_came_from), ...]``. Returns True if
        the seed name changed, in which case handles are regenerated and the new
        ones swept immediately — a corrected spelling is worth more than any
        other single step, so it happens before the pipeline continues.
        """
        nonlocal name, sweep_handles
        if not name:
            return False
        better, source = name, ""
        for cand, where in candidates:
            # A candidate must look like a name, and must not balloon the seed:
            # a title containing the real name is a superset by token test but is
            # not a better label for the person.
            from osint.profile import clean_title_name, contains_platform_word
            cand = clean_title_name(cand) or cand
            if not looks_like_a_person_name(cand, min_words=1):
                continue
            if contains_platform_word(cand):
                continue          # "Ece Güngör på Snapchat" is a page title
            if len(variants.name_key(cand)) > len(variants.name_key(name)) + 2:
                continue
            picked = variants.fuller_name(better, cand)
            if picked != better:
                better, source = picked, where
        if better == name:
            return False
        log(f"[*] name refined: {name!r} -> {better!r} (from {source})")
        out["name_refinement"].append(
            {"from": name, "to": better, "source": source,
             "relation": variants.name_matches(name, better)["relation"]})
        name = better
        if "seed" not in stages:
            return True
        added = [h for h in expand_seed(name, max_handles) if h not in sweep_handles]
        if added and "username" in stages:
            log(f"[*] re-sweeping {len(added)} handle(s) for the refined name ...")
            extra = sweep(added)
            base = out.get("username") or {}
            if base.get("found") is not None:
                base["found"] += extra.get("found", [])
                base["usernames"] = list(dict.fromkeys(base.get("usernames", []) + added))
                base.setdefault("per_username", {}).update(extra.get("per_username", {}))
            else:
                out["username"] = extra
        sweep_handles = list(dict.fromkeys(sweep_handles + added))
        return True

    if "username" in stages and sweep_handles:
        log(f"[*] stage username: sweeping {len(sweep_handles)} handle(s) ...")
        out["username"] = sweep(sweep_handles)
        out["stages_run"].append("username")
        # Instagram/X/Facebook/Threads return the display name with the verdict.
        # If that is a fuller spelling of the seed, act on it right now: every
        # later stage (search, linkedin, records) is more productive with the
        # real name than with the transliteration the caller typed.
        refine_name([(h.get("profile_name", ""), f"{h['site']} profile metadata")
                     for h in (out["username"].get("found") or [])])

    # --- email --------------------------------------------------------------
    if "email" in stages and known_emails:
        from osint import email as email_mod
        log(f"[*] stage email: enriching {len(known_emails[:5])} address(es) ...")
        per_addr = {}
        for addr in known_emails[:5]:
            try:
                per_addr[addr] = email_mod.run(addr, timeout=timeout, skip=("search",))
            except ValueError as exc:
                per_addr[addr] = {"error": str(exc)}
        out["email"] = per_addr
        out["stages_run"].append("email")

    # --- search -------------------------------------------------------------
    if "search" in stages and (name or sweep_handles):
        from osint import websearch
        log("[*] stage search: multi-engine dorks ...")
        out["search"] = websearch.run(
            person=name, handle=sweep_handles[0] if sweep_handles else "",
            extra=" ".join(f'"{x}"' for x in (employer, location) if x),
            max_queries=max_queries, timeout=45.0)
        out["stages_run"].append("search")
        # Search snippets carry the same "Full Name (@handle) • Platform" title
        # the platform itself serves — and they keep working when the platform
        # starts rate-limiting us, so they are a real fallback for refinement.
        from osint.username import _parse_profile_meta
        cands: list[tuple[str, str]] = []
        for r in (out["search"].get("results") or [])[:40]:
            host = _host_of(r["url"])
            if not _is_platform_host(host):
                continue
            if not any(h.lower() in r["url"].lower() for h in sweep_handles):
                continue
            got, _stats = _parse_profile_meta(r.get("title", ""), r.get("snippet", ""))
            if got:
                cands.append((got, f"search result for {host}"))
        refine_name(cands)

    # --- sites: the subject's own website -----------------------------------
    # Run before linkedin/records so a discovered personal site can correct the
    # name and seed those stages properly. A personal site is the single richest
    # page in a person investigation: it is written by them, it names their
    # accounts with rel=me, and search engines routinely fail to surface it.
    if "sites" in stages and (sweep_handles or name):
        cands = personal_site_candidates(sweep_handles, name)
        log(f"[*] stage sites: probing {len(cands)} handle-derived domain(s) ...")
        probes = {d: (lambda dom=d: verify_personal_site(
            dom, name=name, handles=sweep_handles, timeout=min(timeout, 8.0)))
            for d in cands}
        got, _ = fetch.gather(probes, workers=10, timeout=timeout * 3)
        out["sites"] = list(got.values())
        for s in out["sites"]:
            log(f"[*] personal site: {s['url']} (matched on {s['matched_on']})")
        # The landing page rarely holds the contact details; /contact, /about,
        # /impressum and a linked CV PDF do. Crawl those.
        if out["sites"]:
            from osint import profile as profile_mod
            harvests, _ = fetch.gather(
                {s["url"]: (lambda u=s["url"]: profile_mod.harvest_site(
                    u, timeout=timeout, region=region))
                 for s in out["sites"]}, workers=3, timeout=timeout * 4)
            for s in out["sites"]:
                h = harvests.get(s["url"])
                if h:
                    s["harvest"] = h
                    for e in h.get("emails", []):
                        if e not in known_emails:
                            known_emails.append(e)
                            log(f"[*] site contact email: {e}")
        out["stages_run"].append("sites")
        refine_name([((s["identity"] or {}).get("name", ""), s["url"])
                     for s in out["sites"]])

    # --- linkedin -----------------------------------------------------------
    if "linkedin" in stages and name:
        from osint import linkedin
        log("[*] stage linkedin: discovering public profile ...")
        found = linkedin.discover(name, company=employer, location=location)
        out["linkedin"] = found
        if found.get("profiles"):
            try:
                out["linkedin"]["parsed"] = linkedin.lookup(
                    found["profiles"][0]["url"], timeout=timeout)
            except ValueError:
                pass
        out["stages_run"].append("linkedin")

    # --- records ------------------------------------------------------------
    if "records" in stages and name:
        from osint import records
        log("[*] stage records: public registers ...")
        out["records"] = records.run(name, timeout=timeout)
        out["stages_run"].append("records")

    # --- collect every URL worth extracting ---------------------------------
    seen_urls: set[str] = set()

    def collect_urls() -> list[str]:
        urls: list[str] = []

        def add(u: str) -> None:
            u = (u or "").strip()
            key = u.rstrip("/")
            if u.startswith("http") and key not in seen_urls:
                seen_urls.add(key)
                urls.append(u)

        for s in out.get("sites") or []:      # richest pages first
            add(s["url"])
        for hit in (out.get("username") or {}).get("found", []):
            add(hit["url"])
        for lst in ((out.get("search") or {}).get("by_platform") or {}).values():
            for hit in lst[:2]:
                add(hit["url"])
        for p in (out.get("linkedin") or {}).get("profiles", [])[:2]:
            add(p["url"])
        for data in (out.get("email") or {}).values():
            for acct in (data.get("identity", {}) or {}).get("linked_accounts", []):
                add(acct.get("url", ""))
            for u in (data.get("identity", {}) or {}).get("personal_urls", []):
                add(u.get("url", ""))
        for site in (out.get("records") or {}).get("person", {}).get("website", []) or []:
            add(site)
        # Search results that are plausibly the subject's own site. The domain
        # matching the name is the strongest signal, but a result whose TITLE or
        # DESCRIPTION carries the full name is worth fetching too — that is how
        # you find a personal site on a domain that isn't the handle.
        want = _name_tokens(name) if name else set()
        for r in (out.get("search") or {}).get("results", [])[:60]:
            host = _host_of(r["url"])
            if not host or _is_platform_host(host) or not want:
                continue
            if want & _name_tokens(host.replace(".", " ")):
                add(r["url"])                      # domain contains the name
            elif len(want & _name_tokens(f"{r.get('title', '')} "
                                         f"{r.get('snippet', '')}")) >= len(want):
                add(r["url"])                      # title/description names them
        return urls

    # --- profile (with name refinement and recursive expansion) -------------
    declared_urls: set[str] = set()
    if "profile" in stages:
        queue = collect_urls()[:max_profiles]
        for round_no in range(1, max(1, depth) + 1):
            if not queue:
                break
            log(f"[*] stage profile (round {round_no}): "
                f"extracting from {len(queue)} URL(s) ...")
            batch, failures = _extract_batch(queue, timeout=timeout, region=region)
            out["profiles"] += batch
            out.setdefault("profile_failures", {}).update(failures)
            for p in batch:
                for l in p["rel_me"]:
                    declared_urls.add(l["url"].rstrip("/"))

            # A page may carry a fuller spelling than the seed; adopt it and
            # re-sweep before continuing to the next round.
            refine_name(
                [((pr["identity"] or {}).get("name", ""), pr["url"]) for pr in batch]
                + [(((out.get("linkedin") or {}).get("parsed", {})
                     .get("identity", {}).get("name", "")), "linkedin")])

            if round_no >= depth:
                break
            # Recursive expansion. Two rules, both learned the hard way:
            #   * rel=me links are self-declared, so follow them from anywhere.
            #   * ordinary links are only followed from PERSONAL sites. A
            #     platform profile page carries that platform's own footer
            #     ("Strava on Instagram/X/Facebook"), and following those walks
            #     straight into the company's accounts instead of the person's.
            nxt: list[str] = []
            for p in batch:
                on_personal_site = not _is_platform_host(_host_of(p["url"]))
                followable = p["rel_me"] + (p["links"] if on_personal_site else [])
                for l in followable:
                    u = l["url"].rstrip("/")
                    if u not in seen_urls:
                        seen_urls.add(u)
                        nxt.append(l["url"])
            for hit in (out.get("username") or {}).get("found", []):
                u = hit["url"].rstrip("/")
                if u not in seen_urls:
                    seen_urls.add(u)
                    nxt.append(hit["url"])
            queue = nxt[:max_profiles]
        out["stages_run"].append("profile")

    # --- github ---------------------------------------------------------------
    # Public commit metadata carries the author's configured email address. For
    # anyone who writes code this is usually the only place a real address is
    # published, so it is worth a dedicated stage rather than a page scrape.
    if "github" in stages:
        logins: list[str] = []
        for hit in (out.get("username") or {}).get("found", []):
            if hit["site"] == "github" and hit["username"] not in logins:
                logins.append(hit["username"])
        for p in out["profiles"] + [{"rel_me": s.get("profile", {}).get("rel_me", []),
                                     "links": []} for s in (out.get("sites") or [])]:
            for l in p.get("rel_me", []) + p.get("links", []):
                if l.get("platform") == "github" and l.get("handle") not in logins:
                    logins.append(l["handle"])
        for s in out.get("sites") or []:
            for l in (s.get("profile") or {}).get("rel_me", []):
                if l.get("platform") == "github" and l.get("handle") not in logins:
                    logins.append(l["handle"])
        if logins:
            from osint import github as gh
            log(f"[*] stage github: {', '.join(logins[:3])}")
            got, _ = fetch.gather(
                {g: (lambda login=g: gh.run(login, timeout=timeout))
                 for g in logins[:3]}, workers=3, timeout=timeout * 4)
            out["github"] = list(got.values())
            for g in out["github"]:
                for e in g.get("emails", []):
                    if e["kind"] == "real" and e["email"] not in known_emails:
                        known_emails.append(e["email"])
                        log(f"[*] github commit email: {e['email']}")
            refine_name([((g.get("profile") or {}).get("name", ""),
                          f"github/{g['login']} profile") for g in out["github"]])
        out["stages_run"].append("github")

    # --- infra --------------------------------------------------------------
    domains: list[str] = [s["domain"] for s in (out.get("sites") or [])]
    for p in out["profiles"]:
        domains.append(_host_of(p["url"]))
    domains += [addr.split("@")[-1] for addr in known_emails]
    for g in out.get("github", []):
        for e in g.get("emails", []):
            domains.append(e["email"].split("@")[-1])
        blog = (g.get("profile") or {}).get("blog", "")
        if blog:
            domains.append(_host_of(blog if blog.startswith("http") else f"//{blog}"))
    if email_domain:
        domains.append(email_domain)
    domains = list(dict.fromkeys(d for d in domains if is_investigable_domain(d)))

    if "infra" in stages and domains:
        from osint import infra as infra_mod
        log(f"[*] stage infra: profiling {len(domains[:5])} domain(s) ...")
        sources = {d: (lambda dom=d: infra_mod.run(
            dom, active=active_infra, subdomains=subdomains, timeout=timeout))
            for d in domains[:5]}
        got, _ = fetch.gather(sources, workers=3, timeout=timeout * 5)
        out["infra"] = list(got.values())
        out["stages_run"].append("infra")

    # --- correlate ----------------------------------------------------------
    if "correlate" in stages:
        log("[*] stage correlate: scoring accounts ...")
        for data in (out.get("email") or {}).values():
            for acct in (data.get("identity", {}) or {}).get("linked_accounts", []):
                if acct.get("verified"):
                    declared_urls.add((acct.get("url") or "").rstrip("/"))
        wd_handles = (out.get("records") or {}).get("person", {}).get("handles", {}) or {}

        by_url: dict[str, dict] = {}
        for hit in (out.get("username") or {}).get("found", []):
            if hit.get("profile_name") or hit.get("bio"):
                by_url[hit["url"].rstrip("/")] = {
                    "profile_name": hit.get("profile_name", ""),
                    "bio": hit.get("bio", "")}
        for p in out["profiles"]:
            ident = p["identity"] or {}
            enriched = by_url.get(p["url"].rstrip("/"), {})
            by_url[p["url"].rstrip("/")] = {
                "profile_name": ident.get("name", "") or enriched.get("profile_name", ""),
                "bio": " ".join(str(v) for v in (
                    ident.get("headline", ""), ident.get("locality", ""),
                    enriched.get("bio", ""))).strip(),
            }

        all_handles = {h.lower() for h in sweep_handles}
        all_emails = {e.lower() for e in known_emails}
        accounts: list[dict] = []
        pushed: set[str] = set()

        def push(url: str, platform: str, handle: str, **extra) -> None:
            key = (url or "").rstrip("/")
            if not key or key in pushed:
                return
            pushed.add(key)
            enrich = by_url.get(key, {})
            acct = {"url": url, "platform": platform, "handle": handle,
                    "profile_name": enrich.get("profile_name", ""),
                    "bio": enrich.get("bio", ""), **extra}
            conf, score, why = _score_account(
                acct, target_name=name, handles=all_handles, emails=all_emails,
                location=location, employer=employer, declared_urls=declared_urls)
            acct.update({"confidence": conf, "score": score, "evidence": why})
            accounts.append(acct)

        for hit in (out.get("username") or {}).get("found", []):
            push(hit["url"], hit["site"], hit["username"], source="username-sweep")
        for addr, data in (out.get("email") or {}).items():
            for acct in (data.get("identity", {}) or {}).get("linked_accounts", []):
                push(acct.get("url", ""), acct.get("platform", ""),
                     acct.get("username", ""), source=f"gravatar/{addr}",
                     self_declared=bool(acct.get("verified")),
                     declared_by=f"verified Gravatar account for {addr}")
        for p in out["profiles"]:
            for l in p["rel_me"]:
                push(l["url"], l["platform"], l["handle"],
                     source=f"rel=me on {p['url']}", self_declared=True,
                     declared_by=f"rel=me link on {p['url']}")
            if _is_platform_host(_host_of(p["url"])):
                continue   # a platform page's footer links are the PLATFORM's
            for l in p["links"]:
                push(l["url"], l["platform"], l["handle"], source=f"link on {p['url']}")
        for platform, val in wd_handles.items():
            for v in (val if isinstance(val, list) else [val]):
                base = {"x_twitter": "https://x.com/", "instagram": "https://instagram.com/",
                        "facebook": "https://facebook.com/", "github": "https://github.com/",
                        "linkedin": "https://www.linkedin.com/in/"}.get(platform, "")
                if base:
                    push(f"{base}{v}", platform, str(v), source="wikidata",
                         self_declared=True, declared_by="declared on Wikidata")
        # A search hit only becomes an account if the URL or title actually
        # mentions the person. Engines return unrelated videos, subreddits and
        # spam for a name query, and those were arriving as "LOW" accounts.
        want = _name_tokens(name)
        handle_set = {h.lower() for h in sweep_handles}
        for platform, hits in ((out.get("search") or {}).get("by_platform") or {}).items():
            for h in hits[:3]:
                blob = f"{h['url']} {h.get('title', '')}".lower()
                relevant = (any(hd in blob for hd in handle_set)
                            or (want and want <= _name_tokens(blob)))
                if not relevant:
                    continue
                push(h["url"], platform, "", source="websearch",
                     agreement=h.get("agreement", 1))

        rank = {"CONFIRMED": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        accounts.sort(key=lambda a: (rank[a["confidence"]], -a["score"], a["platform"]))
        out["accounts"] = accounts

        # ---- merge every claim, with provenance ----------------------------
        def merged(pairs: list[tuple[str, str]]) -> list[dict]:
            vals: list[dict] = []
            for value, src in pairs:
                value = (value or "").strip()
                if not value:
                    continue
                for x in vals:
                    if x["value"].lower() == value.lower():
                        if src not in x["sources"]:
                            x["sources"].append(src)
                        break
                else:
                    vals.append({"value": value, "sources": [src]})
            return sorted(vals, key=lambda x: -len(x["sources"]))

        def _employers() -> list[str]:
            names = ([e["name"] for e in
                      (out.get("linkedin") or {}).get("parsed", {})
                      .get("experience", [])]
                     + ((out.get("records") or {}).get("person", {})
                        .get("employer") or [])
                     + [(g.get("profile") or {}).get("company", "")
                        for g in out.get("github", [])])
            return [n.strip() for n in dict.fromkeys(names) if n and n.strip()]

        employers = _employers()
        li_parsed = (out.get("linkedin") or {}).get("parsed", {})
        li_ident = li_parsed.get("identity", {})
        rec_person = (out.get("records") or {}).get("person", {})

        name_pairs = [((p["identity"] or {}).get("name", ""), p["url"])
                      for p in out["profiles"]]
        name_pairs += [(h.get("profile_name", ""), f"{h['site']} metadata")
                       for h in (out.get("username") or {}).get("found", [])]
        name_pairs += [((g.get("profile") or {}).get("name", ""),
                        f"github/{g['login']}") for g in out.get("github", [])]
        name_pairs += [(s.get("identity", {}).get("name", ""), s["url"])
                       for s in (out.get("sites") or [])]
        name_pairs += [(li_ident.get("name", ""), "linkedin"),
                       (rec_person.get("name", ""), "wikidata")]
        for addr, data in (out.get("email") or {}).items():
            for n in (data.get("identity", {}) or {}).get("names", []):
                name_pairs.append((n, f"gravatar/{addr}"))

        # Split names into "this is the target" vs "someone else with a hit".
        names_all = merged(name_pairs)
        aliases = [n for n in names_all
                   if not name or variants.name_matches(n["value"], name)["match"]]
        mismatched = [n for n in names_all
                      if n not in aliases and looks_like_a_person_name(n["value"])]

        loc_pairs = [((p["identity"] or {}).get("locality", ""), p["url"])
                     for p in out["profiles"]]
        loc_pairs += [(li_ident.get("locality", ""), "linkedin")]
        loc_pairs += [((g.get("profile") or {}).get("location", ""),
                       f"github/{g['login']}") for g in out.get("github", [])]
        for addr, data in (out.get("email") or {}).items():
            loc_pairs.append(((data.get("identity", {}) or {}).get("location", ""),
                              f"gravatar/{addr}"))

        # Personal data is only merged from a page plausibly ABOUT the target.
        # Search results for a name include forums and spam sites that happily
        # contribute their own contact address, keywords and post dates.
        def about_target(page: dict) -> bool:
            url_l = page["url"].lower()
            pname = (page["identity"] or {}).get("name", "")
            # A name on the page that ISN'T the target settles it: the handle
            # matching is a coincidence, and everything on that page (keywords,
            # emails, dates) belongs to somebody else.
            if name and pname and not variants.name_matches(pname, name)["match"]:
                return False
            if any(h.lower() in url_l for h in sweep_handles):
                return True                      # our handle, no contrary name
            if name and pname and variants.name_matches(pname, name)["match"]:
                return True
            if _is_platform_host(_host_of(page["url"])):
                return False
            # A personal site only counts if it actually names the target.
            text = " ".join(str(v) for v in (page["identity"] or {}).values())
            return bool(name and _name_tokens(name) & _name_tokens(text))

        # A verified personal site and a GitHub account are on-target by
        # construction: the first was matched against the name, the second was
        # reached from a self-declared link or an exact handle hit.
        site_pages = [{"url": s["url"], "identity": s.get("identity", {}),
                       **(s.get("harvest") or {})} for s in (out.get("sites") or [])]
        on_target = [p for p in out["profiles"] if about_target(p)] + site_pages

        phones = merged([(ph["e164"], p["url"]) for p in on_target
                         for ph in p.get("phones", [])])
        for ph in phones:
            src = next((x for p in on_target for x in p.get("phones", [])
                        if x["e164"] == ph["value"]), {})
            ph["country"] = src.get("country", "")
            ph["confidence"] = src.get("confidence", "")
        addresses = merged([(a["formatted"], p["url"]) for p in on_target
                            for a in p.get("addresses", [])])
        # A page's keyword list repeats the person's own name and its language
        # codes ("en", "tr", "fr"); neither is an interest.
        own_tokens = _name_tokens(name)

        def is_interest(value: str) -> bool:
            v = value.strip()
            if len(v) < 3 or v.isdigit():
                return False
            if own_tokens and _name_tokens(v) and _name_tokens(v) <= own_tokens:
                return False
            if v.lower() in {h.lower() for h in sweep_handles}:
                return False          # a handle is an identifier, not an interest
            return v.lower() not in {"en", "tr", "fr", "de", "es", "it", "nl",
                                     "pt", "ru", "ar", "zh", "ja", "portfolio"}

        interests = merged(
            [(i, p["url"]) for p in on_target for i in p.get("interests", [])
             if is_interest(i)]
            + [(topic, f"github/{g['login']}") for g in out.get("github", [])
               for topic in g.get("topics", []) if is_interest(topic)])

        out["identity"] = {
            "names": aliases,
            "other_names_seen": mismatched,
            "locations": merged(loc_pairs),
            "headlines": merged([((p["identity"] or {}).get("headline", ""), p["url"])
                                 for p in out["profiles"]]
                                + [(li_ident.get("headline", ""), "linkedin")]),
            "birth_date": rec_person.get("birth_date") or [],
            "birth_hints": sorted({b for p in on_target
                                   for b in p.get("birth_hints", [])
                                   if _plausible_birth(b)}),
            "employers": employers,
            "education": list(dict.fromkeys(
                [e["name"] for e in li_parsed.get("education", [])]
                + (rec_person.get("educated_at") or []))),
            "emails": sorted({e for p in on_target for e in p.get("emails", [])}
                             | set(known_emails)
                             | {e["email"] for g in out.get("github", [])
                                for e in g.get("emails", []) if e["kind"] == "real"}),
            "phones": phones,
            "addresses": addresses,
            "interests": interests,
            "occupations": rec_person.get("occupation") or [],
            "citizenship": rec_person.get("citizenship") or [],
            "confirmed_accounts": [a["url"] for a in accounts
                                   if a["confidence"] == "CONFIRMED"],
        }

        # ---- entity index, Maltego-style -----------------------------------
        breaches = sorted({b for data in (out.get("email") or {}).values()
                           for b in (data.get("breaches", {}) or {}).get("names", [])})
        out["entities"] = {
            "person": [n["value"] for n in aliases],
            "alias": [n["value"] for n in aliases[1:]],
            "email": out["identity"]["emails"],
            "phone": [p["value"] for p in phones],
            "address": [a["value"] for a in addresses],
            "location": [l["value"] for l in out["identity"]["locations"]],
            "social_profile": [a["url"] for a in accounts
                               if a["confidence"] in ("CONFIRMED", "HIGH", "MEDIUM")],
            "handle": sorted({a["handle"] for a in accounts if a.get("handle")}),
            "organization": out["identity"]["employers"],
            "education": out["identity"]["education"],
            "interest": [i["value"] for i in interests],
            "breach": breaches,
            "domain": [i["domain"] for i in out["infra"]],
            "ip": sorted({ip for i in out["infra"]
                          for ip in i.get("ips", []) + i.get("subdomain_ips", [])}),
            "subdomain": sorted({s for i in out["infra"]
                                 for s in i.get("subdomains", [])}),
            "netblock": sorted({pfx for i in out["infra"] for a in i.get("asn", [])
                                for pfx in a.get("prefixes", [])[:5]}),
            "asn": sorted({a["asn"] for i in out["infra"] for a in i.get("asn", [])}),
            "dns_record": sorted({f"{k} {v}" for i in out["infra"]
                                  for k, vs in (i.get("dns") or {}).items()
                                  for v in vs[:3]}),
            "technology": sorted({t for i in out["infra"]
                                  for t in (i.get("http") or {}).get("tech", [])}),
            "registrar": sorted({(i.get("rdap") or {}).get("registrar", "")
                                 for i in out["infra"]} - {""}),
        }
        out["stages_run"].append("correlate")

    # --- what to do next ----------------------------------------------------
    steps: list[str] = []
    if out["name_refinement"]:
        last = out["name_refinement"][-1]
        steps.append(f"Name was refined to '{last['to']}' mid-run and re-swept. "
                     "Re-run with --name that value to start from it.")
    low = [a for a in out["accounts"] if a["confidence"] == "LOW"]
    if low:
        steps.append(f"{len(low)} LOW-confidence accounts are handle matches with "
                     "nothing else behind them — open a couple before believing any.")
    if out["identity"].get("other_names_seen"):
        steps.append("Some profiles carry names that do NOT match the target — "
                     "those hits are probably different people; see other_names_seen.")
    if out["identity"].get("emails"):
        steps.append("Run the email stage on any newly discovered address: "
                     f"--email {out['identity']['emails'][0]}")
    if domains and "infra" not in out["stages_run"]:
        steps.append(f"Domains found ({', '.join(domains[:3])}) — add the infra "
                     "stage for RDAP/DNS/ASN/tech.")
    if not out["accounts"] and not (out["identity"].get("names")
                                    or out["identity"].get("emails")):
        steps.append("Nothing found. Check the name spelling, try a handle you "
                     "already know (--handle), and remember most private people "
                     "have a genuinely small public footprint.")
    steps.append("Re-run a single stage with different inputs instead of the whole "
                 "sweep, e.g. --stages username --handle <corrected-handle>.")
    out["next_steps"] = steps
    return out


def _result_table(res: dict) -> list[str]:
    """Render every useful entity as one aligned table (the --result-table view)."""
    ent = res.get("entities") or {}
    idt = res.get("identity") or {}
    if not ent:
        return ["(no entities — run the correlate stage)"]

    rows: list[tuple[str, str, str]] = []

    def add(kind: str, value: str, note: str = "") -> None:
        if value:
            rows.append((kind, str(value)[:78], note[:46]))

    for n in idt.get("names", []):
        add("NAME", n["value"], f"{len(n['sources'])} source(s)")
    for n in idt.get("other_names_seen", []):
        add("NAME (mismatch)", n["value"], "likely a different person")
    for b in idt.get("birth_date", []):
        add("DATE OF BIRTH", b, "wikidata")
    for b in idt.get("birth_hints", [])[:5]:
        add("DOB HINT", b, "unverified, from page text")
    for l in idt.get("locations", []):
        add("LOCATION", l["value"], f"{len(l['sources'])} source(s)")
    for a in idt.get("addresses", []):
        add("ADDRESS", a["value"], f"{len(a['sources'])} source(s)")
    for p in idt.get("phones", []):
        add("PHONE", p["value"], f"{p.get('country', '')} ({p.get('confidence', '')})")
    for e in idt.get("emails", []):
        add("EMAIL", e)
    for h in ent.get("handle", []):
        add("HANDLE", h)
    for a in res.get("accounts", []):
        if a["confidence"] != "LOW":
            add(f"PROFILE ({a['confidence']})", a["url"], a["platform"])
    for o in idt.get("employers", []):
        add("ORGANIZATION", o, "employer")
    for e in idt.get("education", []):
        add("EDUCATION", e)
    for o in idt.get("occupations", []):
        add("OCCUPATION", o)
    for c in idt.get("citizenship", []):
        add("CITIZENSHIP", c)
    for i in idt.get("interests", [])[:25]:
        add("INTEREST", i["value"])
    for b in ent.get("breach", []):
        add("BREACH", b)
    for g in res.get("github", []):
        prof = g.get("profile") or {}
        add("GITHUB ACCOUNT", prof.get("html_url", ""), f"id {g.get('user_id', '')}")
        for e in g.get("emails", []):
            add("EMAIL (git commit)", e["email"],
                "real address" if e["kind"] == "real" else "noreply proxy")
        for o in g.get("orgs", []):
            add("ORGANIZATION", o["login"], "github org")
    for s in res.get("sites", []):
        add("WEBSITE", s.get("url", ""), f"matched on {s.get('matched_on', '')}")
        for pg in (s.get("harvest") or {}).get("pages_fetched", [])[1:]:
            add("PAGE CRAWLED", pg, "contact/CV page")
    for inf in res.get("infra", []):
        add("DOMAIN", inf.get("domain", ""),
            (inf.get("rdap") or {}).get("registrar", ""))
        for ip in inf.get("ips", []):
            add("IP", ip, inf.get("domain", ""))
        for sub in inf.get("subdomains", []):
            add("SUBDOMAIN", sub, inf.get("domain", ""))
        for ip in inf.get("subdomain_ips", []):
            add("IP (subdomain)", ip, inf.get("domain", ""))
        for a in inf.get("asn", []):
            add("ASN", a.get("asn", ""), a.get("holder", ""))
            for pfx in a.get("prefixes", [])[:3]:
                add("NETBLOCK", pfx, a.get("asn", ""))
        for ns in inf.get("nameservers", [])[:4]:
            add("DNS (NS)", ns, inf.get("domain", ""))
        for mx in inf.get("mx", [])[:4]:
            add("DNS (MX)", mx, inf.get("domain", ""))
        for t in (inf.get("http") or {}).get("tech", []):
            add("TECHNOLOGY", t, inf.get("domain", ""))
        for rel in inf.get("related_domains", [])[:6]:
            add("RELATED DOMAIN", rel, inf.get("domain", ""))

    if not rows:
        return ["(nothing found)"]
    w1 = max(len(r[0]) for r in rows)
    w2 = max(len(r[1]) for r in rows)
    sep = "-" * (w1 + w2 + 52)
    out = [sep, f"{'ENTITY'.ljust(w1)}  {'VALUE'.ljust(w2)}  NOTE", sep]
    out += [f"{k.ljust(w1)}  {v.ljust(w2)}  {n}" for k, v, n in rows]
    out.append(sep)
    out.append(f"{len(rows)} entities")
    return out


def _compact_lines(res: dict, result_table: bool = False) -> list[str]:
    t = res["target"]
    lines = [f"# person: {t['name'] or ', '.join(t['handles']) or ', '.join(t['emails'])}",
             f"# stages run: {', '.join(res['stages_run']) or 'none'}"]
    for ref in res.get("name_refinement", []):
        lines.append(f"# name refined: {ref['from']!r} -> {ref['to']!r} "
                     f"({ref['relation']}, via {ref['source']})")

    if result_table:
        return lines + _result_table(res)

    idt = res.get("identity") or {}
    if idt:
        lines.append("## IDENTITY (merged, with provenance)")
        for n in idt.get("names", [])[:5]:
            lines.append(f"  name       {n['value']}   [{len(n['sources'])} source(s)]")
        for l in idt.get("locations", [])[:3]:
            lines.append(f"  location   {l['value']}   [{len(l['sources'])} source(s)]")
        for h in idt.get("headlines", [])[:3]:
            lines.append(f"  headline   {h['value'][:110]}")
        if idt.get("birth_date"):
            lines.append(f"  born       {', '.join(str(b) for b in idt['birth_date'])}")
        if idt.get("birth_hints"):
            lines.append(f"  dob hints  {', '.join(idt['birth_hints'][:5])}  (unverified)")
        for p in idt.get("phones", []):
            lines.append(f"  phone      {p['value']}  {p.get('country', '')} "
                         f"({p.get('confidence', '')})")
        for a in idt.get("addresses", [])[:5]:
            lines.append(f"  address    {a['value']}")
        if idt.get("employers"):
            lines.append(f"  employers  {', '.join(idt['employers'][:8])}")
        if idt.get("education"):
            lines.append(f"  education  {', '.join(idt['education'][:8])}")
        if idt.get("emails"):
            lines.append(f"  emails     {', '.join(idt['emails'][:8])}")
        if idt.get("interests"):
            lines.append("  interests  "
                         + ", ".join(i["value"] for i in idt["interests"][:20]))
        if idt.get("other_names_seen"):
            lines.append("  ! other names on matched pages (probably other people): "
                         + ", ".join(n["value"] for n in idt["other_names_seen"][:5]))

    accounts = res.get("accounts", [])
    if accounts:
        lines.append(f"## ACCOUNTS ({len(accounts)}) — grouped by confidence")
        current = ""
        for a in accounts:
            if a["confidence"] != current:
                current = a["confidence"]
                lines.append(f"### {current}")
            lines.append(f"  {a['platform']:<16} {a['url']}")
            for e in a["evidence"][:3]:
                lines.append(f"      · {e}")

    for inf in res.get("infra", []):
        lines.append(f"## INFRA {inf.get('domain', '')}")
        r = inf.get("rdap") or {}
        if r.get("registrar"):
            lines.append(f"  registrar  {r['registrar']}  (created {r.get('created', '')})")
        if inf.get("ips"):
            lines.append(f"  ips        {', '.join(inf['ips'][:6])}")
        for a in inf.get("asn", []):
            lines.append(f"  asn        {a.get('asn', '')} {a.get('holder', '')}")
        if (inf.get("http") or {}).get("tech"):
            lines.append(f"  tech       {', '.join(inf['http']['tech'])}")

    u = res.get("username") or {}
    if u.get("found") is not None:
        lines.append(f"## STAGE username: {len(u.get('found', []))} hits for "
                     f"{', '.join(u.get('usernames', [])[:12])}")
    s = res.get("search") or {}
    if s:
        lines.append(f"## STAGE search: {s.get('total_unique', 0)} URLs from "
                     f"{len(s.get('engines_used', []))} engines")
    li = res.get("linkedin") or {}
    if li.get("profiles"):
        lines.append(f"## STAGE linkedin: {len(li['profiles'])} candidate profile(s)")
        for p in li["profiles"][:3]:
            lines.append(f"  {p['url']}  {p['title'][:70]}")
    rec = (res.get("records") or {}).get("person") or {}
    if rec.get("name"):
        lines.append(f"## STAGE records: {rec['name']} — {rec.get('description', '')}")
    if res.get("profiles"):
        lines.append(f"## STAGE profile: extracted {len(res['profiles'])} page(s)")

    lines.append("## NEXT")
    lines += [f"  - {x}" for x in res.get("next_steps", [])]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.person",
        description="Run every osint tool on one person and correlate the results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.person --name "Ada Lovelace"\n'
                '  python -m osint.person --handle torvalds --result-table\n'
                '  python -m osint.person --name "Ada Lovelace" --email ada@example.com \\\n'
                '      --employer "Analytical Engines" --location London --region GB\n'
                '  python -m osint.person --handle torvalds --stages username,profile,correlate\n'
                f'\nstages: {", ".join(STAGES)}\n'),
    )
    p.add_argument("--name", default="", help="Target's full name.")
    p.add_argument("--handle", action="append", default=[],
                   help="Known handle (repeatable).")
    p.add_argument("--email", action="append", default=[],
                   help="Known email address (repeatable).")
    p.add_argument("--email-domain", default="",
                   help="Mail domain for address permutation (e.g. employer's).")
    p.add_argument("--location", default="", help="City/country, to disambiguate.")
    p.add_argument("--employer", default="", help="Company, to disambiguate.")
    p.add_argument("--region", default="",
                   help="ISO country code for reading phone numbers/postcodes (TR, GB...).")
    p.add_argument("--stages", default="",
                   help=f"Comma-separated subset of: {', '.join(STAGES)}")
    p.add_argument("--depth", type=int, default=2,
                   help="Profile expansion rounds (default 2; 1 = no recursion).")
    p.add_argument("--max-handles", type=int, default=8,
                   help="Derived handle candidates to sweep (default 8).")
    p.add_argument("--max-profiles", type=int, default=12,
                   help="URLs fetched per profile round (default 12).")
    p.add_argument("--max-queries", type=int, default=6,
                   help="Search dork queries (default 6, run 4 at a time).")
    p.add_argument("--no-subdomains", action="store_true",
                   help="Skip subdomain enumeration in the infra stage.")
    p.add_argument("--active-infra", action="store_true",
                   help="Let the infra stage connect to hosts (HTTP/TLS).")
    p.add_argument("--result-table", action="store_true",
                   help="Print one aligned table of every entity found.")
    p.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.name or args.handle or args.email):
        parser.print_help(sys.stderr)
        return 2
    stages = tuple(s.strip() for s in args.stages.split(",") if s.strip()) or STAGES
    try:
        res = run(name=args.name, handles=args.handle, emails=args.email,
                  email_domain=args.email_domain, location=args.location,
                  employer=args.employer, region=args.region, stages=stages,
                  max_handles=args.max_handles, max_profiles=args.max_profiles,
                  max_queries=args.max_queries, depth=args.depth,
                  active_infra=args.active_infra,
                  subdomains=not args.no_subdomains, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json,
         lines=_compact_lines(res, result_table=args.result_table))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
