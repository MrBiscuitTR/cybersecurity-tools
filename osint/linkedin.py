"""Read public LinkedIn profiles: career history, education, location, headline.

LinkedIn is the densest public source of career and education data about a
person, and it is the one people assume can't be read without an account. Public
profiles — the ones anyone gets from a Google result — embed a complete
schema.org ``Person`` block: employers with start/end dates, schools with dates,
job titles, city, country, headline and photo. This module fetches that page with
browser-realistic headers and parses that block.

Two entry points:

    lookup(vanity_or_url)   parse one public profile
    discover(name, ...)     find profile URLs for a person by name, via the
                            multi-engine search layer (site:linkedin.com/in),
                            because LinkedIn's own search needs a session

Limits, stated plainly:
  * Only PUBLIC profiles are readable. If the owner restricted their profile, or
    LinkedIn decides to challenge the request, you get an authwall — reported as
    ``authwall: true`` rather than silently returning nothing.
  * HTTP 999 is LinkedIn's rate-limit/deny code. It means "ask again later", NOT
    "no such profile" — the two are indistinguishable from outside, so this
    never reports 999 as an absent profile.
  * Connections, contact info, and anything behind a login are out of reach, and
    this makes no attempt at them: no session cookies, no credential use, no
    scraping of the authenticated app.

This reads public pages the same way a search-engine crawler does. It is still
worth knowing that LinkedIn's terms discourage automated collection; keep volume
low, and prefer ``discover`` (which asks search engines, not LinkedIn) when you
only need to locate a profile.

Safety: read-only. GETs a public URL, follows redirects, parses HTML. No login,
no writes, no connection requests, nothing that touches the target's account.

Usage:
    python -m osint.linkedin williamhgates
    python -m osint.linkedin https://www.linkedin.com/in/williamhgates --json
    python -m osint.linkedin --discover "Ada Lovelace" --company "Analytical Engines"
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse as up

from common.output import emit, log
from osint import fetch, profile

_VANITY_RE = re.compile(r"^[A-Za-z0-9\-%_.]{3,120}$")


def normalize(target: str) -> tuple[str, str]:
    """Turn a vanity name or any LinkedIn URL into ``(vanity, profile_url)``.

    Accepts ``williamhgates``, ``/in/williamhgates``,
    ``linkedin.com/in/williamhgates``, regional hosts (``tr.linkedin.com``), and
    URLs with tracking query strings.

    Raises:
        ValueError: If no usable vanity name can be extracted.
    """
    t = target.strip().rstrip("/")
    if "linkedin.com" in t.lower():
        path = up.urlparse(t if "://" in t else "https://" + t).path
        m = re.search(r"/in/([^/?#]+)", path)
        if not m:
            raise ValueError(f"not a LinkedIn /in/ profile URL: {target!r}")
        vanity = m.group(1)
    else:
        vanity = t.lstrip("/").removeprefix("in/")
    vanity = up.unquote(vanity)
    if not _VANITY_RE.match(vanity):
        raise ValueError(f"not a plausible LinkedIn vanity name: {target!r}")
    return vanity, f"https://www.linkedin.com/in/{up.quote(vanity)}"


def lookup(target: str, *, timeout: float = 20.0, render: bool = False) -> dict:
    """Fetch and parse one public LinkedIn profile.

    Args:
        target: Vanity name or profile URL.
        timeout: Request timeout in seconds.
        render: Use Playwright if installed (rarely needed — the JSON-LD is in
            the server-rendered HTML).

    Returns:
        ``{"vanity","url","http_status","authwall","found","identity",
        "experience","education","raw"}`` where ``experience``/``education`` are
        lists of ``{"name","url","start","end"}``.

    Raises:
        ValueError: If ``target`` isn't a usable profile reference.
    """
    vanity, url = normalize(target)
    log(f"[*] fetching {url} ...")

    if render:
        r = fetch.render(url, timeout=timeout)
        body = r.get("html", "") if r.get("rendered") else ""
        status = r.get("status", 0)
        if not body:
            resp = fetch.get(url, timeout=timeout, retries=2)
            body, status = resp.text, resp.status
    else:
        resp = fetch.get(url, timeout=timeout, retries=2)
        body, status = resp.text, resp.status

    authwall = ("authwall" in body.lower() or "join linkedin" in body.lower()[:6000]
                or status in (999, 403, 429))
    data = profile.extract(body, base_url=url) if body else {
        "identity": {}, "links": [], "rel_me": [], "emails": [], "phones": [],
        "birth_hints": [], "jsonld_person": {}, "opengraph": {}, "title": "",
        "h1": "", "raw_jsonld_types": [], "text_sample": ""}

    person = data.get("jsonld_person", {}) or {}
    ident = data.get("identity", {}) or {}
    found = bool(person.get("name") or ident.get("name")) and not authwall

    # og:description on LinkedIn packs a summary: "<headline> · Experience: X ·
    # Education: Y · Location: Z". Useful when JSON-LD is missing.
    og_desc = (data.get("opengraph", {}) or {}).get("og:description", "")
    summary: dict[str, str] = {}
    for label in ("Experience", "Education", "Location"):
        m = re.search(rf"{label}:\s*([^·]+)", og_desc)
        if m:
            summary[label.lower()] = m.group(1).strip()

    identity = {
        "name": person.get("name") or ident.get("name", ""),
        "given_name": person.get("given_name") or ident.get("given_name", ""),
        "family_name": person.get("family_name") or ident.get("family_name", ""),
        "headline": person.get("headline") or (og_desc.split("·")[0].strip()
                                               if og_desc else ""),
        "job_titles": person.get("job_titles", []),
        "locality": person.get("locality") or summary.get("location", ""),
        "country": person.get("country", ""),
        "image": person.get("image", ""),
    }

    steps: list[str] = []
    if status == 999:
        steps.append("HTTP 999 = LinkedIn rate-limited this request. It does NOT mean "
                     "the profile is absent. Wait and retry, or open the URL in a "
                     "browser.")
    if authwall and status != 999:
        steps.append("Authwall: this profile isn't public, or LinkedIn challenged the "
                     "request. Try --discover to find search-engine snippets, which "
                     "often carry the headline and employer anyway.")
    if found:
        steps.append(f"Confirmed name '{identity['name']}' — feed it to osint.variants "
                     "for handle candidates, then sweep with osint.username.")
        if identity["locality"]:
            steps.append(f"Location '{identity['locality']}' is a strong disambiguator; "
                         "pass it as --extra to osint.websearch.")
        emp = [e["name"] for e in person.get("works_for", [])]
        if emp:
            steps.append(f"Employers {', '.join(emp[:3])} give you corporate email "
                         "domains — run osint.variants --email-domain on each.")
    return {"vanity": vanity, "url": url, "http_status": status,
            "authwall": authwall, "found": found, "identity": identity,
            "experience": person.get("works_for", []),
            "education": person.get("alumni_of", []),
            "og_summary": summary, "links": data.get("links", []),
            "next_steps": steps}


def discover(
    name: str,
    *,
    company: str = "",
    location: str = "",
    keywords: str = "",
    timeout: float = 45.0,
) -> dict:
    """Find LinkedIn profile URLs for a person using search engines.

    Asks the multi-engine search layer rather than LinkedIn, so it works even
    when LinkedIn itself is rate-limiting, and it surfaces the result snippet —
    which usually contains the headline and current employer even for profiles
    that would show an authwall if fetched directly.

    Args:
        name: Person's full name.
        company: Employer, to disambiguate a common name.
        location: City/country, same purpose.
        keywords: Any other terms (school, job title, skill).
        timeout: Per-query budget.

    Returns:
        ``{"name","queries","profiles","other_hits","engines_used"}`` where
        ``profiles`` are ``linkedin.com/in/...`` URLs with their snippets.

    Raises:
        ValueError: If ``name`` is empty.
    """
    if not name.strip():
        raise ValueError("give a name to search for")
    from osint import websearch

    extra = " ".join(f'"{x}"' for x in (company, location, keywords) if x.strip())
    queries = [f'site:linkedin.com/in "{name}" {extra}'.strip(),
               f'site:linkedin.com/in "{name}"',
               f'linkedin "{name}" {extra}'.strip()]
    profiles: dict[str, dict] = {}
    other: list[dict] = []
    engines: set[str] = set()

    for q in queries:
        log(f"[*] {q}")
        res = websearch.search(q, timeout=timeout)
        engines.update(res["engines_used"])
        for r in res["results"]:
            if re.search(r"linkedin\.com/in/", r["url"], re.I):
                try:
                    vanity, clean = normalize(r["url"])
                except ValueError:
                    continue
                cur = profiles.setdefault(clean, {
                    "vanity": vanity, "url": clean, "title": r["title"],
                    "snippet": r["snippet"], "agreement": r["agreement"]})
                if len(r["snippet"]) > len(cur["snippet"]):
                    cur["snippet"] = r["snippet"]
                cur["agreement"] = max(cur["agreement"], r["agreement"])
            elif len(other) < 25:
                other.append(r)

    ranked = sorted(profiles.values(), key=lambda p: -p["agreement"])
    steps = ["Run `python -m osint.linkedin <vanity>` on the best match to parse the "
             "full career and education history.",
             "The result title is usually 'Name - Headline | LinkedIn' — that alone "
             "confirms employer and role without fetching the profile."]
    if not ranked:
        steps = ["No indexed public profile found. The person may have a private "
                 "profile, or the name spelling differs — try osint.websearch "
                 "--person with the name alone to find the spelling they use."]
    return {"name": name, "queries": queries, "profiles": ranked,
            "other_hits": other, "engines_used": sorted(engines), "next_steps": steps}


def _compact_lines(res: dict) -> list[str]:
    if "profiles" in res:  # discover mode
        lines = [f"# linkedin discover: {res['name']}  "
                 f"({len(res['profiles'])} profiles via {len(res['engines_used'])} engines)"]
        for p in res["profiles"]:
            lines.append(f"  [{p['agreement']}x] {p['url']}")
            if p["title"]:
                lines.append(f"        {p['title'][:130]}")
            if p["snippet"]:
                lines.append(f"        {p['snippet'][:220]}")
        if res["other_hits"]:
            lines.append(f"## OTHER HITS ({len(res['other_hits'])})")
            for r in res["other_hits"][:10]:
                lines.append(f"  {r['url']}")
        lines.append("## NEXT")
        lines += [f"  - {s}" for s in res["next_steps"]]
        return lines

    lines = [f"# linkedin: {res['url']}  [HTTP {res['http_status']}]"
             + ("  AUTHWALL" if res["authwall"] else "")
             + ("  FOUND" if res["found"] else "")]
    i = res["identity"]
    if any(i.values()):
        lines.append("## IDENTITY")
        for k in ("name", "headline", "locality", "country"):
            if i.get(k):
                lines.append(f"  {k:<10} {i[k]}")
        if i.get("job_titles"):
            lines.append(f"  {'titles':<10} {', '.join(i['job_titles'])}")
    if res["experience"]:
        lines.append(f"## EXPERIENCE ({len(res['experience'])})")
        for e in res["experience"]:
            span = (f"  {e['start']}–{e['end'] or 'present'}" if e.get("start") else "")
            lines.append(f"  {e['name']}{span}")
            if e.get("url"):
                lines.append(f"    {e['url']}")
    if res["education"]:
        lines.append(f"## EDUCATION ({len(res['education'])})")
        for e in res["education"]:
            span = (f"  {e['start']}–{e['end'] or '?'}" if e.get("start") else "")
            lines.append(f"  {e['name']}{span}")
    if res["og_summary"]:
        lines.append("## SUMMARY (from page metadata)")
        for k, v in res["og_summary"].items():
            lines.append(f"  {k:<10} {v}")
    if res["next_steps"]:
        lines.append("## NEXT")
        lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.linkedin",
        description="Parse public LinkedIn profiles, or find them by name via search engines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.linkedin williamhgates\n'
                '  python -m osint.linkedin linkedin.com/in/williamhgates --json\n'
                '  python -m osint.linkedin --discover "Ada Lovelace" --company Acme\n'),
    )
    p.add_argument("target", nargs="?", help="Vanity name or profile URL.")
    p.add_argument("--discover", default="", metavar="NAME",
                   help="Find profile URLs for this person via search engines.")
    p.add_argument("--company", default="", help="Employer (disambiguates --discover).")
    p.add_argument("--location", default="", help="City/country (disambiguates --discover).")
    p.add_argument("--keywords", default="", help="Extra terms for --discover.")
    p.add_argument("--timeout", type=float, default=20.0, help="Timeout (default 20).")
    p.add_argument("--render", action="store_true", help="Render with Playwright if installed.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.target and not args.discover:
        parser.print_help(sys.stderr)
        return 2
    try:
        if args.discover:
            res = discover(args.discover, company=args.company, location=args.location,
                           keywords=args.keywords, timeout=max(args.timeout, 45.0))
        else:
            res = lookup(args.target, timeout=args.timeout, render=args.render)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
