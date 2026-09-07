"""Extract a person's identity data from any public profile page or website.

The step that turns "the handle exists" into facts. Give it a profile URL — a
GitHub page, a personal site, a Mastodon profile, a conference bio, a LinkedIn
public profile — and it pulls out the name, bio, location, employer, education,
dates, email addresses, phone numbers, and, most valuably, **every other account
the page links to**.

That last one matters more than the rest combined. A guessed link between two
accounts is a hypothesis; a page where the person themselves put a link to their
other profile is evidence. ``rel="me"`` links are explicit identity claims and
are reported separately for exactly that reason.

Extraction runs in layers, best-quality first, and every layer's raw output is
kept so an operator can see where a claim came from and disagree with it:

    1. JSON-LD (schema.org Person/Organization) — structured, authoritative;
       this is how LinkedIn, personal sites and many CMSes publish identity
    2. microformats2 rel=me / h-card — the explicit identity-claim standard
    3. OpenGraph + Twitter cards — title, description, avatar, first/last name
    4. plain HTML — <title>, <h1>, meta description
    5. regex sweep of the whole body — emails (including "name [at] host"
       obfuscation), phone numbers, and outbound links to ~40 known platforms

Dependencies: standard library only (via :mod:`osint.fetch`). No API key. An
optional ``--render`` flag uses Playwright for JS-only pages if it is installed;
everything works without it.

Safety: read-only. One GET of a page you point it at, following redirects like a
browser. It does not crawl, does not follow links it finds, and writes nothing.

Usage:
    python -m osint.profile https://github.com/torvalds
    python -m osint.profile https://www.linkedin.com/in/williamhgates --json
    python -m osint.profile https://example.com/about --render
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

from common.output import emit, log
from osint import fetch

# (host fragment, platform, regex capturing the handle, max path segments).
# The segment cap is what separates a profile from site furniture:
# github.com/torvalds is 1 segment and a person; github.com/features/copilot is
# 2 and a product page. 0 means "don't check" (handle lives in the query string).
PLATFORM_LINKS: list[tuple[str, str, str, int]] = [
    ("github.com", "github", r"^/([A-Za-z0-9-]+)/?$", 1),
    ("gitlab.com", "gitlab", r"^/([A-Za-z0-9._-]+)/?$", 1),
    ("codeberg.org", "codeberg", r"^/([A-Za-z0-9._-]+)/?$", 1),
    ("linkedin.com", "linkedin", r"^/in/([A-Za-z0-9%\-_.]+)", 2),
    ("twitter.com", "x/twitter", r"^/([A-Za-z0-9_]+)/?$", 1),
    ("x.com", "x/twitter", r"^/([A-Za-z0-9_]+)/?$", 1),
    ("instagram.com", "instagram", r"^/([A-Za-z0-9._]+)/?$", 1),
    ("facebook.com", "facebook", r"^/([A-Za-z0-9.]+)/?$", 1),
    ("threads.net", "threads", r"^/@([A-Za-z0-9._]+)", 1),
    ("t.me", "telegram", r"^/([A-Za-z0-9_]+)/?$", 1),
    ("youtube.com", "youtube", r"^/(?:@|c/|user/|channel/)([A-Za-z0-9._-]+)", 2),
    ("tiktok.com", "tiktok", r"^/@([A-Za-z0-9._]+)", 1),
    ("reddit.com", "reddit", r"^/u(?:ser)?/([A-Za-z0-9_-]+)", 2),
    ("mastodon", "mastodon", r"^/@([A-Za-z0-9_]+)", 1),
    ("bsky.app", "bluesky", r"^/profile/([A-Za-z0-9._-]+)", 2),
    ("keybase.io", "keybase", r"^/([A-Za-z0-9_]+)/?$", 1),
    ("stackoverflow.com", "stackoverflow", r"^/users/(\d+)", 3),
    ("medium.com", "medium", r"^/@([A-Za-z0-9._-]+)", 1),
    ("substack.com", "substack", r"", 0),
    ("dev.to", "dev.to", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("hashnode", "hashnode", r"^/@([A-Za-z0-9_-]+)", 1),
    ("news.ycombinator.com", "hackernews", r"id=([A-Za-z0-9_-]+)", 0),
    ("twitch.tv", "twitch", r"^/([A-Za-z0-9_]+)/?$", 1),
    ("steamcommunity.com", "steam", r"^/(?:id|profiles)/([A-Za-z0-9_-]+)", 2),
    ("lichess.org", "lichess", r"^/@/([A-Za-z0-9_-]+)", 2),
    ("chess.com", "chess.com", r"^/member/([A-Za-z0-9_-]+)", 2),
    ("soundcloud.com", "soundcloud", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("spotify.com", "spotify", r"/user/([A-Za-z0-9_-]+)", 2),
    ("behance.net", "behance", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("dribbble.com", "dribbble", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("flickr.com", "flickr", r"^/people/([A-Za-z0-9_@-]+)", 2),
    ("deviantart.com", "deviantart", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("patreon.com", "patreon", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("ko-fi.com", "ko-fi", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("buymeacoffee.com", "buymeacoffee", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("linktr.ee", "linktree", r"^/([A-Za-z0-9_.]+)/?$", 1),
    ("about.me", "about.me", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("gravatar.com", "gravatar", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("orcid.org", "orcid", r"^/([0-9X-]{16,25})/?$", 1),
    ("scholar.google", "scholar", r"user=([A-Za-z0-9_-]+)", 0),
    ("researchgate.net", "researchgate", r"^/profile/([A-Za-z0-9_-]+)", 2),
    ("goodreads.com", "goodreads", r"^/user/show/([A-Za-z0-9_-]+)", 3),
    ("letterboxd.com", "letterboxd", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("strava.com", "strava", r"^/athletes/([A-Za-z0-9_-]+)", 2),
    ("last.fm", "last.fm", r"^/user/([A-Za-z0-9_-]+)", 2),
    ("kaggle.com", "kaggle", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("huggingface.co", "huggingface", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("hackerone.com", "hackerone", r"^/([A-Za-z0-9_-]+)/?$", 1),
    ("bugcrowd.com", "bugcrowd", r"^/([A-Za-z0-9_-]+)/?$", 1),
]

# Path segments that are site furniture rather than a person, on any platform.
RESERVED_HANDLES = frozenset("""
about help support contact login signin signup join register terms privacy legal
policies security settings account notifications explore trending topics
collections events sponsors marketplace features pricing enterprise business
solutions resources developer developers docs documentation blog news press
careers jobs team teams premium pro plus upgrade download downloads apps app
mobile api status site sitemap search find discover home index new create
customer-stories why-github mcp copilot actions codespaces issues packages
sponsors readme translate share embed watch playlist results feed shorts
hashtag tag tags category categories p c u user users profile profiles page
pages i intent hashtags directory local groups events pages public dir company
school showcase learning posts pulse jobs games music video store
""".split())

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
# "name [at] example [dot] com" and friends — deliberate obfuscation is a signal
# that the address is real and the owner expected scraping. The separator must be
# bracketed or space-delimited: an unanchored "at" matches INSIDE ordinary words
# ("notific-at-ions" -> notific@ions.learn), which floods the output with junk.
_OBFUS_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]{2,})"
    r"(?:\s+at\s+|\s*[\[({<]\s*(?:at|@)\s*[\])}>]\s*)"
    r"([A-Za-z0-9.-]{2,})"
    r"(?:\s+dot\s+|\s*[\[({<]\s*(?:dot|\.)\s*[\])}>]\s*|\.)"
    r"([A-Za-z]{2,24})\b", re.I)
# Any 2-letter ccTLD is accepted; beyond that a whitelist, because the address
# regex will happily read "...datasette.net.Disclosures" as a domain otherwise.
_COMMON_TLDS = frozenset("""
com org net edu gov mil int info biz name pro dev app io co ai me tv cc ly sh
xyz online site tech store shop blog cloud digital email live life world today
news media agency company group team works studio design software systems solutions
network computer network security host press wiki space fun art gallery photo
academy school university institute foundation ngo org.uk co.uk ac.uk gov.uk
com.tr edu.tr gov.tr org.tr net.tr com.au co.jp co.kr com.br com.cn co.in
""".split())
_PHONE_RE = re.compile(r"(?<![\d-])(\+\d{1,3}[\s.-]?)?(\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?![\d-])")
# A date only counts as a birth hint when a birth word introduces it — an
# unqualified year on a page is just a year. Covers 1800-2099 (a 19xx-only year
# pattern silently drops every historical figure) and the three shapes people
# write: "10 December 1815", "05/12/1990", and a bare "born in 1815".
_BIRTH_RE = re.compile(
    r"(?i)\b(?:born|birth\s*(?:day|date)?|d\.?o\.?b\.?|doğum(?:\s*tarihi)?)\b[^.\n]{0,40}?"
    r"("
    r"(?:\d{1,2}\s+)?"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s*"
    r"(?:\d{1,2},?\s*)?(?:1[89]|20)\d{2}"
    r"|\d{1,2}[./-]\d{1,2}[./-](?:1[89]|20)\d{2}"
    r"|(?:1[89]|20)\d{2}"
    r")")
_TAG_RE = re.compile(r"<(script|style)\b.*?</\1>", re.S | re.I)


def _plausible_email(addr: str) -> bool:
    """Filter regex noise: asset filenames, all-numeric mailboxes, and made-up
    TLDs produced by a sentence boundary ("...example.net. Disclosures")."""
    local, _, domain = addr.partition("@")
    if not local or not domain or local.isdigit():
        return False
    if re.search(r"\.(png|jpe?g|gif|svg|webp|css|js|ico|woff2?)$", addr, re.I):
        return False
    tld = domain.rsplit(".", 1)[-1]
    two = ".".join(domain.rsplit(".", 2)[-2:])
    return len(tld) == 2 or tld in _COMMON_TLDS or two in _COMMON_TLDS


def _text_of(page_html: str) -> str:
    """Strip tags/scripts and collapse whitespace, for regex sweeps."""
    body = _TAG_RE.sub(" ", page_html)
    body = re.sub(r"<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", html.unescape(body)).strip()


def _meta(page_html: str, key: str) -> str:
    """Read a <meta property|name="key" content="..."> value."""
    for attr in ("property", "name", "itemprop"):
        m = re.search(rf'<meta[^>]+{attr}=["\']{re.escape(key)}["\'][^>]*'
                      rf'content=["\'](.*?)["\']', page_html, re.I | re.S)
        if not m:
            m = re.search(rf'<meta[^>]+content=["\'](.*?)["\'][^>]*'
                          rf'{attr}=["\']{re.escape(key)}["\']', page_html, re.I | re.S)
        if m:
            return html.unescape(m.group(1)).strip()
    return ""


def _json_ld(page_html: str) -> list[dict]:
    """Extract and flatten every JSON-LD block, including @graph children."""
    out: list[dict] = []
    for m in re.finditer(
            r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            page_html, re.S | re.I):
        raw = m.group(1).strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                if "@graph" in node:
                    stack.extend(node["@graph"] if isinstance(node["@graph"], list)
                                 else [node["@graph"]])
                out.append(node)
    return out


def _is_masked(name: str) -> bool:
    """True if a site redacted this value for logged-out visitors.

    LinkedIn serves entries like ``***** ********** ******`` in the JSON-LD of a
    public profile — real structure, hidden content. Passing those through means
    an employer list full of asterisks, so they're dropped at the source.
    """
    stripped = name.replace("*", "").replace("·", "").strip()
    return "*" in name and len(stripped) < max(3, len(name) * 0.4)


def _org_names(value: Any) -> list[dict]:
    """Normalize schema.org Organization/EducationalOrganization values."""
    items = value if isinstance(value, list) else [value]
    out = []
    for it in items:
        if isinstance(it, str):
            out.append({"name": it.strip(), "url": "", "start": "", "end": ""})
        elif isinstance(it, dict):
            member = it.get("member") or {}
            if isinstance(member, list):
                member = member[0] if member else {}
            out.append({"name": str(it.get("name", "")).strip(),
                        "url": it.get("url", ""),
                        "start": str(member.get("startDate", "") or ""),
                        "end": str(member.get("endDate", "") or "")})
    return [o for o in out if o["name"] and not _is_masked(o["name"])]


def _person_from_jsonld(nodes: list[dict]) -> dict:
    """Pull the richest schema.org Person node into a flat identity dict."""
    best: dict = {}
    for node in nodes:
        types = node.get("@type", "")
        types = types if isinstance(types, list) else [types]
        if "Person" not in types:
            continue
        addr = node.get("address") or {}
        if isinstance(addr, list):
            addr = addr[0] if addr else {}
        jt = node.get("jobTitle", "")
        cand = {
            "name": str(node.get("name", "")).strip(),
            "given_name": str(node.get("givenName", "")).strip(),
            "family_name": str(node.get("familyName", "")).strip(),
            "headline": str(node.get("disambiguatingDescription", "")
                            or node.get("description", "")).strip(),
            "job_titles": [jt] if isinstance(jt, str) and jt else list(jt or []),
            "locality": str(addr.get("addressLocality", "") if isinstance(addr, dict) else ""),
            "country": str(addr.get("addressCountry", "") if isinstance(addr, dict) else ""),
            "birth_date": str(node.get("birthDate", "") or ""),
            "email": str(node.get("email", "") or "").replace("mailto:", ""),
            "telephone": str(node.get("telephone", "") or ""),
            "works_for": _org_names(node.get("worksFor")),
            "alumni_of": _org_names(node.get("alumniOf")),
            "same_as": ([node["sameAs"]] if isinstance(node.get("sameAs"), str)
                        else list(node.get("sameAs") or [])),
            "image": (node.get("image", {}).get("contentUrl", "")
                      if isinstance(node.get("image"), dict) else str(node.get("image", ""))),
        }
        if sum(1 for v in cand.values() if v) > sum(1 for v in best.values() if v):
            best = cand
    return best


def classify_link(url: str) -> dict | None:
    """Map an outbound URL to ``{"platform","handle","url"}`` if it is a profile
    link, else None.

    Rejects site navigation two ways: a path-segment cap per platform (a profile
    lives at ``/handle``, a product page at ``/features/x``) and a reserved-word
    list, so a GitHub page's own menu doesn't come back as 84 "accounts".
    """
    try:
        p = urlparse(url)
    except ValueError:
        return None
    host = (p.netloc or "").lower()
    if not host:
        return None
    segments = [s for s in (p.path or "").split("/") if s]
    for frag, platform, pat, max_segs in PLATFORM_LINKS:
        if frag not in host:
            continue
        if max_segs and len(segments) > max_segs:
            continue
        if platform == "substack":
            handle = host.split(".")[0]
        else:
            target = f"{p.path}?{p.query}" if not max_segs else (p.path or "/")
            m = re.search(pat, target) if pat else None
            handle = m.group(1) if m and m.groups() else ""
        if not handle or handle.lower() in RESERVED_HANDLES:
            continue
        return {"platform": platform, "handle": handle, "url": url}
    return None


def extract(page_html: str, base_url: str = "") -> dict:
    """Run every extraction layer over one page's HTML.

    Args:
        page_html: Raw HTML.
        base_url: URL the HTML came from (used to resolve relative links).

    Returns:
        ``{"identity", "links", "rel_me", "emails", "phones", "birth_hints",
        "jsonld_person", "opengraph", "title", "description", "raw_jsonld_types"}``.
    """
    nodes = _json_ld(page_html)
    person = _person_from_jsonld(nodes)
    text = _text_of(page_html)

    og = {k: _meta(page_html, k) for k in
          ("og:title", "og:description", "og:image", "og:url", "og:site_name",
           "profile:first_name", "profile:last_name", "profile:username",
           "twitter:title", "twitter:description", "twitter:creator", "description")}
    og = {k: v for k, v in og.items() if v}

    title_m = re.search(r"<title[^>]*>(.*?)</title>", page_html, re.S | re.I)
    title = html.unescape(title_m.group(1)).strip() if title_m else ""
    h1_m = re.search(r"<h1[^>]*>(.*?)</h1>", page_html, re.S | re.I)
    h1 = _text_of(h1_m.group(1)) if h1_m else ""

    # Links: every href, classified against the platform table. rel="me" is kept
    # separately because it is an explicit, self-declared identity claim.
    links: list[dict] = []
    rel_me: list[dict] = []
    seen: set[str] = set()
    own_host = urlparse(base_url).netloc.lower().removeprefix("www.") if base_url else ""
    for m in re.finditer(r"<a\b([^>]*)>", page_html, re.I):
        attrs = m.group(1)
        href_m = re.search(r'href=["\'](.*?)["\']', attrs, re.I)
        if not href_m:
            continue
        href = html.unescape(href_m.group(1)).strip()
        if href.startswith("mailto:") or not href or href.startswith("#"):
            continue
        full = urljoin(base_url, href) if base_url else href
        # Links back into the page's own site are navigation, not other accounts;
        # we already know which platform we're on.
        if own_host and urlparse(full).netloc.lower().removeprefix("www.") == own_host:
            continue
        info = classify_link(full)
        if not info or full in seen:
            continue
        seen.add(full)
        is_me = bool(re.search(r'rel=["\'][^"\']*\bme\b', attrs, re.I))
        (rel_me if is_me else links).append(info)

    # Also mine JSON-LD sameAs — same kind of self-declaration.
    for u in person.get("same_as", []):
        info = classify_link(str(u))
        if info and info["url"] not in seen:
            seen.add(info["url"])
            rel_me.append(info)

    emails = sorted({e for e in (x.lower() for x in _EMAIL_RE.findall(text))
                     if _plausible_email(e)})
    for local, dom, tld in _OBFUS_RE.findall(text):
        cand = f"{local}@{dom}.{tld}".lower()
        if cand not in emails and _plausible_email(cand):
            emails.append(cand)

    phones = sorted({re.sub(r"\s{2,}", " ", p.group(0)).strip()
                     for p in _PHONE_RE.finditer(text)
                     if 9 <= len(re.sub(r"\D", "", p.group(0))) <= 15})

    identity = {
        "name": person.get("name") or og.get("og:title", "").split(" - ")[0].strip() or h1,
        "given_name": person.get("given_name") or og.get("profile:first_name", ""),
        "family_name": person.get("family_name") or og.get("profile:last_name", ""),
        "username": og.get("profile:username", ""),
        "headline": person.get("headline") or og.get("og:description",
                                                     og.get("description", "")),
        "locality": person.get("locality", ""),
        "country": person.get("country", ""),
        "job_titles": person.get("job_titles", []),
        "works_for": person.get("works_for", []),
        "alumni_of": person.get("alumni_of", []),
        "birth_date": person.get("birth_date", ""),
        "image": person.get("image") or og.get("og:image", ""),
    }
    return {"identity": {k: v for k, v in identity.items() if v},
            "links": links, "rel_me": rel_me, "emails": emails, "phones": phones,
            "birth_hints": sorted({m.group(1).strip() for m in _BIRTH_RE.finditer(text)}),
            "jsonld_person": person, "opengraph": og, "title": title, "h1": h1,
            "raw_jsonld_types": sorted({str(n.get("@type", "")) for n in nodes if n.get("@type")}),
            "text_sample": text[:1200]}


def run(url: str, *, timeout: float = 20.0, render: bool = False) -> dict:
    """Fetch a page and extract everything identity-related from it.

    Args:
        url: Profile or website URL (scheme optional; https is assumed).
        timeout: Request timeout in seconds.
        render: Use a headless browser (Playwright) for JS-only pages. Falls
            back to the plain fetch, with a note, if Playwright isn't installed.

    Returns:
        The :func:`extract` dict plus ``{"url","final_url","http_status",
        "blocked","rendered","next_steps"}``.

    Raises:
        ValueError: If ``url`` is not a usable http(s) URL.
    """
    u = url.strip()
    if not u:
        raise ValueError("empty url")
    if "://" not in u:
        u = "https://" + u
    if urlparse(u).scheme not in ("http", "https"):
        raise ValueError(f"not an http(s) url: {url!r}")

    rendered, note = False, ""
    if render:
        log(f"[*] rendering {u} in a headless browser ...")
        r = fetch.render(u, timeout=timeout)
        if r.get("rendered"):
            body, status, final = r["html"], r.get("status", 0), u
            rendered = True
        else:
            note = f"render failed ({r.get('error')}); fell back to plain fetch"
            log(f"[!] {note}")
            resp = fetch.get(u, timeout=timeout, retries=2)
            body, status, final = resp.text, resp.status, resp.final_url
    else:
        log(f"[*] fetching {u} ...")
        resp = fetch.get(u, timeout=timeout, retries=2)
        body, status, final = resp.text, resp.status, resp.final_url

    blocked = False if rendered else fetch.Response(
        u, final, status, body.encode("utf-8", "replace"), None, 0.0).blocked

    res = extract(body, base_url=final or u)
    res.update({"url": u, "final_url": final, "http_status": status,
                "blocked": blocked, "rendered": rendered, "note": note})

    steps: list[str] = []
    if blocked:
        steps.append("Page looks like a bot wall — retry, or use --render if "
                     "Playwright is installed.")
    if res["rel_me"]:
        steps.append("rel=me / sameAs links are SELF-DECLARED — treat those "
                     "accounts as the same person unless contradicted.")
    if res["links"]:
        steps.append("Run osint.profile on the linked profiles to widen the graph.")
    if res["emails"]:
        steps.append("Feed the emails to osint.email for breach/Gravatar/git pivots.")
    if res["identity"].get("name"):
        steps.append(f"Re-run osint.variants --name \"{res['identity']['name']}\" "
                     "to generate handles from the REAL name you just recovered.")
    if not res["identity"] and not res["links"]:
        steps.append("Nothing structured on this page; try the search engines "
                     "(osint.websearch) instead.")
    res["next_steps"] = steps
    return res


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# profile: {res['final_url'] or res['url']}  [HTTP {res['http_status']}]"
             + ("  RENDERED" if res["rendered"] else "")
             + ("  BLOCKED" if res["blocked"] else "")]
    if res.get("note"):
        lines.append(f"# note: {res['note']}")

    ident = res["identity"]
    if ident:
        lines.append("## IDENTITY")
        for k in ("name", "given_name", "family_name", "username", "headline",
                  "locality", "country", "birth_date"):
            if ident.get(k):
                lines.append(f"  {k:<12} {ident[k]}")
        for k, label in (("job_titles", "title"), ):
            if ident.get(k):
                lines.append(f"  {label:<12} {', '.join(ident[k])}")
        for org in ident.get("works_for", []):
            span = f" ({org['start']}–{org['end'] or 'present'})" if org["start"] else ""
            lines.append(f"  employer     {org['name']}{span}")
        for org in ident.get("alumni_of", []):
            span = f" ({org['start']}–{org['end']})" if org["start"] else ""
            lines.append(f"  education    {org['name']}{span}")
    else:
        lines.append("## IDENTITY  (nothing structured found)")
        if res["title"]:
            lines.append(f"  title        {res['title']}")

    if res["rel_me"]:
        lines.append(f"## SELF-DECLARED ACCOUNTS ({len(res['rel_me'])}) — strongest evidence")
        for l in res["rel_me"]:
            lines.append(f"  {l['platform']:<14} {l['handle']:<20} {l['url']}")
    if res["links"]:
        lines.append(f"## LINKED ACCOUNTS ({len(res['links'])}) — on-page links, verify each")
        for l in res["links"]:
            lines.append(f"  {l['platform']:<14} {l['handle']:<20} {l['url']}")
    if res["emails"]:
        lines.append(f"## EMAILS ({len(res['emails'])})")
        lines += [f"  {e}" for e in res["emails"]]
    if res["phones"]:
        lines.append(f"## PHONE-SHAPED STRINGS ({len(res['phones'])}) — noisy, verify")
        lines += [f"  {p}" for p in res["phones"]]
    if res["birth_hints"]:
        lines.append("## DATE-OF-BIRTH HINTS (context-matched, verify)")
        lines += [f"  {b}" for b in res["birth_hints"]]
    if res["next_steps"]:
        lines.append("## NEXT")
        lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.profile",
        description="Extract name/bio/location/employer/education/links from a profile page.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m osint.profile https://github.com/torvalds\n"
                "  python -m osint.profile linkedin.com/in/williamhgates --json\n"
                "  python -m osint.profile https://example.com/about --render\n"),
    )
    p.add_argument("url", nargs="?", help="Profile or website URL.")
    p.add_argument("--timeout", type=float, default=20.0, help="Timeout (default 20).")
    p.add_argument("--render", action="store_true",
                   help="Render JS with Playwright if installed (optional dependency).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.url:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(args.url, timeout=args.timeout, render=args.render)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
