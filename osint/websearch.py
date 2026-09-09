"""Query many search engines at once and merge the results.

No single engine is trustworthy for OSINT: each indexes a different slice of the
web, each rate-limits, and any one of them can start serving a captcha the day
you need it. So this queries up to nine in parallel and merges — the same
many-sources design as ``recon.subdomains``. A URL returned by four engines is a
much stronger signal than one returned by one, and that agreement count is
reported.

Engines (all keyless unless noted):
    duckduckgo_html   html.duckduckgo.com/html   precise parser
    duckduckgo_lite   lite.duckduckgo.com/lite   precise parser
    bing              www.bing.com               generic parser + ck/a decoder
    brave             search.brave.com           generic parser
    startpage         www.startpage.com          generic parser (Google index)
    yahoo             search.yahoo.com           generic parser + RU= decoder
    mojeek            www.mojeek.com             independent index
    marginalia        old-search.marginalia.nu   indie web; OFF by default — it
                                                 ignores site:/quotes
    searxng           $SEARX_URL or public list  meta-engine: one query covers
                                                 Google/Bing/Brave/Wikipedia at once
    brave_api         api.search.brave.com       needs $BRAVE_API_KEY
    google_cse        customsearch.googleapis.com  needs $GOOGLE_CSE_KEY + $GOOGLE_CSE_CX
    serper            google.serper.dev          needs $SERPER_API_KEY

Keyed engines are used automatically when the env var is present and skipped
silently when it isn't — so this degrades from "twelve engines" to "eight" rather
than failing.

Also builds the dork sets that make people-search work: ``--person`` runs the
name against every major social platform with ``site:`` restrictions, which is
the only honest way to cover Instagram, Facebook, LinkedIn, Pinterest, Reddit and
friends — they are login-walled to direct requests but their public profiles are
indexed.

Safety: read-only. Sends search queries and reads public result pages. No
scraping of the linked sites themselves (that's :mod:`osint.profile`), no writes.

Usage:
    python -m osint.websearch '"Ada Lovelace" site:github.com'
    python -m osint.websearch --person "Cagan Efe Calidag" --json
    python -m osint.websearch --person "Ada Lovelace" --handle adalovelace
    python -m osint.websearch 'site:linkedin.com/in "acme corp" "security"'
"""

from __future__ import annotations

import argparse
import base64
import html
import os
import random
import re
import sys
import urllib.parse as up

from common.output import emit, log
from osint import fetch

# Social platforms worth a site:-restricted query in --person mode. These are
# exactly the platforms that block direct profile probing but are indexed.
SOCIAL_SITES: list[tuple[str, str]] = [
    ("linkedin", "linkedin.com/in"),
    ("instagram", "instagram.com"),
    ("facebook", "facebook.com"),
    ("x/twitter", "x.com OR site:twitter.com"),
    ("reddit", "reddit.com"),
    ("tiktok", "tiktok.com"),
    ("pinterest", "pinterest.com"),
    ("threads", "threads.net"),
    ("youtube", "youtube.com"),
    ("spotify", "open.spotify.com"),
    ("medium", "medium.com"),
    ("substack", "substack.com"),
    ("github", "github.com"),
    ("tumblr", "tumblr.com"),
    ("vk", "vk.com"),
    ("xing", "xing.com"),
    ("crunchbase", "crunchbase.com"),
    ("twitch", "twitch.tv"),
    ("soundcloud", "soundcloud.com"),
    ("strava", "strava.com"),
    ("goodreads", "goodreads.com"),
    ("researchgate", "researchgate.net"),
    ("stackoverflow", "stackoverflow.com"),
    ("quora", "quora.com"),
    ("gravatar", "gravatar.com"),
]

# Hosts that are engine chrome, not results.
_NAV_HOSTS = re.compile(
    r"(duckduckgo|bing\.com|microsoft\.com|msn\.com|brave\.com|startpage\.com|"
    r"ixquick|yahoo\.com|oath\.com|verizonmedia|mojeek\.com|marginalia\.nu|"
    r"google\.[a-z.]+|w3\.org|mozilla\.org|apple\.com|adobe\.com)", re.I)


def _clean_html(text: str) -> str:
    """Strip tags/entities and collapse whitespace, then drop the breadcrumb
    prefix engines glue onto result titles ("Githubhttps://github.com > x  Real
    Title" -> "Real Title")."""
    t = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).strip()
    if "://" in t:
        stripped = re.sub(r"^.*?https?://[^\s›»|]+(?:\s*[›»]\s*[^\s›»]+)*\s*", "", t)
        if len(stripped) >= 8:  # only if something meaningful survives
            t = stripped
        else:
            # The whole title was a breadcrumb (some engines emit nothing else).
            # Drop the URL tokens rather than hand back a fake "title".
            t = re.sub(r"https?://\S+", " ", t)
            t = re.sub(r"\s+", " ", t).strip(" ›»·|-–—")
    return t.strip(" ·|-–—")


def _unwrap(url: str) -> str:
    """Unwrap engine click-tracking redirects to the real target URL."""
    if "uddg=" in url:  # DuckDuckGo
        m = re.search(r"uddg=([^&]+)", url)
        if m:
            return up.unquote(m.group(1))
    if "/ck/a" in url or "u=a1" in url:  # Bing base64url
        m = re.search(r"[?&]u=a1([A-Za-z0-9_-]+)", url)
        if m:
            s = m.group(1)
            try:
                return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode(
                    "utf-8", "replace")
            except (ValueError, TypeError):
                return ""
    if "/RU=" in url:  # Yahoo
        m = re.search(r"/RU=([^/]+)/R", url)
        if m:
            return up.unquote(m.group(1))
    if url.startswith("//"):
        return "https:" + url
    return url


def _parse_generic(page: str, engine_host: str) -> list[dict]:
    """Extract (url, title) pairs from any engine's result HTML.

    Deliberately markup-agnostic: engines rewrite their CSS classes constantly,
    but they all emit anchors to the results. Filters out the engine's own
    navigation, then de-duplicates by URL keeping the longest anchor text.
    """
    out: dict[str, dict] = {}
    for m in re.finditer(r"<a\b[^>]*href=[\"'](.*?)[\"'][^>]*>(.*?)</a>", page, re.S | re.I):
        raw, label = html.unescape(m.group(1)).strip(), _clean_html(m.group(2))
        url = _unwrap(raw)
        if not url.startswith(("http://", "https://")):
            continue
        host = up.urlparse(url).netloc
        if not host or _NAV_HOSTS.search(host) or engine_host in host:
            continue
        if len(label) < 4 or len(url) > 500:
            continue
        prev = out.get(url)
        if not prev or len(label) > len(prev["title"]):
            out[url] = {"url": url, "title": label, "snippet": ""}
    return list(out.values())


def _parse_ddg_html(page: str) -> list[dict]:
    """Precise parser for html.duckduckgo.com (has clean result classes)."""
    out = []
    for m in re.finditer(
            r'<a[^>]+class="result__a"[^>]*href="(.*?)"[^>]*>(.*?)</a>', page, re.S):
        url = _unwrap(html.unescape(m.group(1)))
        if url.startswith("http"):
            out.append({"url": url, "title": _clean_html(m.group(2)), "snippet": ""})
    for i, m in enumerate(re.finditer(
            r'class="result__snippet"[^>]*>(.*?)</a>', page, re.S)):
        if i < len(out):
            out[i]["snippet"] = _clean_html(m.group(1))
    return out


def _parse_ddg_lite(page: str) -> list[dict]:
    """Parser for lite.duckduckgo.com (results are uddg= wrapped links)."""
    out, seen = [], set()
    for m in re.finditer(r'<a[^>]+href="([^"]*uddg=[^"]+)"[^>]*>(.*?)</a>', page, re.S):
        url = _unwrap(html.unescape(m.group(1)))
        title = _clean_html(m.group(2))
        if url.startswith("http") and url not in seen and len(title) > 3:
            seen.add(url)
            out.append({"url": url, "title": title, "snippet": ""})
    return out


def _search_html(name: str, url: str, host: str, parser=None, **kw) -> list[dict]:
    r = fetch.get(url, timeout=kw.pop("timeout", 18.0), retries=1, **kw)
    if not r.ok or r.blocked:
        return []
    results = (parser or _parse_generic)(r.text, host) if parser else _parse_generic(r.text, host)
    for i, res in enumerate(results):
        res["engine"], res["rank"] = name, i + 1
    return results


# --- engine implementations ------------------------------------------------

def _ddg_html(q: str, n: int) -> list[dict]:
    return _search_html("duckduckgo_html",
                        f"https://html.duckduckgo.com/html/?q={up.quote(q)}",
                        "duckduckgo", _parse_ddg_html)


def _ddg_lite(q: str, n: int) -> list[dict]:
    return _search_html("duckduckgo_lite",
                        f"https://lite.duckduckgo.com/lite/?q={up.quote(q)}",
                        "duckduckgo", _parse_ddg_lite)


def _bing(q: str, n: int) -> list[dict]:
    return _search_html("bing",
                        f"https://www.bing.com/search?q={up.quote(q)}&count={min(n, 50)}",
                        "bing.com")


def _brave(q: str, n: int) -> list[dict]:
    return _search_html("brave", f"https://search.brave.com/search?q={up.quote(q)}",
                        "brave.com")


def _startpage(q: str, n: int) -> list[dict]:
    return _search_html("startpage",
                        f"https://www.startpage.com/sp/search?query={up.quote(q)}",
                        "startpage.com")


def _yahoo(q: str, n: int) -> list[dict]:
    return _search_html("yahoo", f"https://search.yahoo.com/search?p={up.quote(q)}",
                        "yahoo.com")


def _mojeek(q: str, n: int) -> list[dict]:
    return _search_html("mojeek", f"https://www.mojeek.com/search?q={up.quote(q)}",
                        "mojeek.com")


def _marginalia(q: str, n: int) -> list[dict]:
    return _search_html("marginalia",
                        f"https://old-search.marginalia.nu/search?query={up.quote(q)}",
                        "marginalia.nu")


# Public SearXNG instances that returned parseable results when last checked
# (2026-09). A SearXNG instance is itself a meta-engine — one query there fans
# out to Google, Bing, Brave, Wikipedia and more without any API key — so it is
# the single highest-value engine in this list. Public instances are volatile:
# they rate-limit hard (HTTP 429), disable the JSON API, and disappear, which is
# why several are tried in random order. Point $SEARX_URL at your own instance
# to skip all of that.
PUBLIC_SEARXNG = (
    "https://opnxng.com",
    "https://paulgo.io",
    "https://www.gruble.de",
    "https://searxng.site",
    "https://search.mdosch.de",
    "https://search.inetol.net",
    "https://baresearch.org",
    "https://search.hbubli.cc",
)


def _parse_searxng(page: str, _host: str = "") -> list[dict]:
    """Parse SearXNG's result markup: <article class="result"> blocks."""
    out = []
    for block in re.findall(r"<article[^>]+class=\"[^\"]*result[^\"]*\".*?</article>",
                            page, re.S | re.I):
        m = re.search(r"<h3[^>]*>\s*<a[^>]+href=[\"'](.*?)[\"'][^>]*>(.*?)</a>",
                      block, re.S | re.I)
        if not m:
            m = re.search(r"<a[^>]+href=[\"'](.*?)[\"'][^>]+class=[\"'][^\"']*url_header",
                          block, re.S | re.I)
            if not m:
                continue
            url, title = html.unescape(m.group(1)), ""
        else:
            url, title = html.unescape(m.group(1)), _clean_html(m.group(2))
        if not url.startswith("http"):
            continue
        snip = re.search(r"<p[^>]+class=[\"'][^\"']*content[^\"']*[\"'][^>]*>(.*?)</p>",
                         block, re.S | re.I)
        out.append({"url": url, "title": title,
                    "snippet": _clean_html(snip.group(1)) if snip else ""})
    return out


def _searxng(q: str, n: int) -> list[dict]:
    """SearXNG — a meta-engine, so one query here covers many upstream engines.

    Uses $SEARX_URL when set (comma-separate several; a local instance such as
    ``http://localhost:8080`` is ideal — no rate limits, and you can enable the
    JSON API). Otherwise falls back to public instances in random order. JSON is
    tried first and HTML parsed when the instance has JSON disabled, which most
    public ones do.
    """
    configured = [u.strip().rstrip("/") for u in
                  os.environ.get("SEARX_URL", "").split(",") if u.strip()]
    instances = configured or random.sample(PUBLIC_SEARXNG, k=min(4, len(PUBLIC_SEARXNG)))

    for base in instances:
        data, _ = fetch.get_json(f"{base}/search?q={up.quote(q)}&format=json", timeout=18)
        if isinstance(data, dict) and data.get("results"):
            return [{"url": it.get("url", ""), "title": _clean_html(it.get("title", "")),
                     "snippet": _clean_html(it.get("content", "")),
                     "engine": "searxng", "rank": i + 1}
                    for i, it in enumerate(data["results"][:n]) if it.get("url")]
        r = fetch.get(f"{base}/search?q={up.quote(q)}", timeout=18, retries=0)
        if r.ok and not r.blocked:
            hits = _parse_searxng(r.text)
            if hits:
                for i, hit in enumerate(hits[:n]):
                    hit["engine"], hit["rank"] = "searxng", i + 1
                return hits[:n]
    return []


def _brave_api(q: str, n: int) -> list[dict]:
    key = os.environ.get("BRAVE_API_KEY", "")
    if not key:
        return []
    data, _ = fetch.get_json(
        f"https://api.search.brave.com/res/v1/web/search?q={up.quote(q)}&count={min(n, 20)}",
        headers={"X-Subscription-Token": key, "Accept": "application/json"}, timeout=20)
    items = (data or {}).get("web", {}).get("results", [])
    return [{"url": it.get("url", ""), "title": _clean_html(it.get("title", "")),
             "snippet": _clean_html(it.get("description", "")),
             "engine": "brave_api", "rank": i + 1} for i, it in enumerate(items)]


def _google_cse(q: str, n: int) -> list[dict]:
    key, cx = os.environ.get("GOOGLE_CSE_KEY", ""), os.environ.get("GOOGLE_CSE_CX", "")
    if not (key and cx):
        return []
    data, _ = fetch.get_json(
        "https://customsearch.googleapis.com/customsearch/v1"
        f"?key={key}&cx={cx}&q={up.quote(q)}&num={min(n, 10)}", timeout=20)
    return [{"url": it.get("link", ""), "title": it.get("title", ""),
             "snippet": it.get("snippet", ""), "engine": "google_cse", "rank": i + 1}
            for i, it in enumerate((data or {}).get("items", []))]


def _serper(q: str, n: int) -> list[dict]:
    key = os.environ.get("SERPER_API_KEY", "")
    if not key:
        return []
    import json as _json
    data, _ = fetch.get_json(
        "https://google.serper.dev/search",
        headers={"X-API-KEY": key, "Content-Type": "application/json"},
        data=_json.dumps({"q": q, "num": min(n, 20)}).encode(), timeout=20)
    return [{"url": it.get("link", ""), "title": it.get("title", ""),
             "snippet": it.get("snippet", ""), "engine": "serper", "rank": i + 1}
            for i, it in enumerate((data or {}).get("organic", []))]


ENGINES = {
    "duckduckgo_html": _ddg_html, "duckduckgo_lite": _ddg_lite, "bing": _bing,
    "brave": _brave, "startpage": _startpage, "yahoo": _yahoo, "mojeek": _mojeek,
    "marginalia": _marginalia, "searxng": _searxng, "brave_api": _brave_api,
    "google_cse": _google_cse, "serper": _serper,
}
KEYED_ENGINES = {"brave_api": "BRAVE_API_KEY", "serper": "SERPER_API_KEY",
                 "google_cse": "GOOGLE_CSE_KEY", "searxng": "SEARX_URL"}
# Engines that ignore `site:` and quoted phrases and answer the loose words
# instead. On a people search that means unrelated forums, videos and adult
# sites arriving as "results" for a name. Still selectable with --engines when
# you deliberately want an independent index.
NON_OPERATOR_ENGINES = {"marginalia"}


def person_dorks(name: str, *, handle: str = "", extra: str = "") -> list[str]:
    """Build the query set for finding a person.

    Args:
        name: Full name; quoted as a phrase so engines don't split it.
        handle: A known username, searched bare and across social sites.
        extra: Extra terms (employer, city, school) ANDed into the general
            queries — this is what turns 10,000 "John Smith" hits into 5.

    Returns:
        Query strings, general first then site-restricted per platform.
    """
    n = f'"{name.strip()}"' if name.strip() else ""
    ex = f" {extra.strip()}" if extra.strip() else ""
    out: list[str] = []
    if n:
        out += [f"{n}{ex}", f"{n}{ex} (cv OR resume OR bio OR profile)",
                f"{n}{ex} (email OR contact OR @)"]
    if handle:
        out += [f'"{handle}"{ex}', f'"{handle}" (profile OR account OR github)']
    for _, site in SOCIAL_SITES:
        term = n or f'"{handle}"'
        if not term:
            continue
        out.append(f"site:{site} {term}{ex}" if " OR " not in site
                   else f"(site:{site}) {term}{ex}")
    if handle:
        for _, site in SOCIAL_SITES[:8]:
            if " OR " not in site:
                out.append(f'site:{site} "{handle}"')
    return out


def search(
    query: str,
    *,
    engines: list[str] | None = None,
    count: int = 20,
    timeout: float = 45.0,
) -> dict:
    """Run one query across many engines concurrently and merge the results.

    Args:
        query: The search query (supports ``site:``, quotes, OR — pass through).
        engines: Engine subset; None = all available (keyed ones auto-skip
            without their env var).
        count: Results requested per engine.
        timeout: Overall wall-clock budget.

    Returns:
        ``{"query","results","engines_used","engines_down","total_unique"}``.
        Each result has ``url,title,snippet,engines,agreement,best_rank`` where
        ``agreement`` is how many engines returned that URL.
    """
    chosen = engines or [e for e in ENGINES
                         if (e not in KEYED_ENGINES or os.environ.get(KEYED_ENGINES[e]))
                         and e not in NON_OPERATOR_ENGINES]
    sources = {name: (lambda f=ENGINES[name], q=query, c=count: f(q, c))
               for name in chosen if name in ENGINES}
    got, down = fetch.gather(sources, workers=min(8, len(sources) or 1), timeout=timeout)

    merged: dict[str, dict] = {}
    for engine, items in got.items():
        for it in items:
            url = (it.get("url") or "").strip()
            if not url:
                continue
            key = url.rstrip("/")
            cur = merged.setdefault(key, {"url": url, "title": it.get("title", ""),
                                          "snippet": it.get("snippet", ""),
                                          "engines": [], "best_rank": 999})
            if engine not in cur["engines"]:
                cur["engines"].append(engine)
            cur["best_rank"] = min(cur["best_rank"], it.get("rank", 999))
            if len(it.get("title", "")) > len(cur["title"]):
                cur["title"] = it["title"]
            if len(it.get("snippet", "")) > len(cur["snippet"]):
                cur["snippet"] = it["snippet"]

    results = sorted(merged.values(),
                     key=lambda r: (-len(r["engines"]), r["best_rank"], r["url"]))
    for r in results:
        r["agreement"] = len(r["engines"])
    return {"query": query, "results": results, "engines_used": sorted(got),
            "engines_down": down, "total_unique": len(results)}


def run(
    query: str = "",
    *,
    person: str = "",
    handle: str = "",
    extra: str = "",
    engines: list[str] | None = None,
    count: int = 20,
    max_queries: int = 12,
    timeout: float = 45.0,
) -> dict:
    """Search for a raw query, or run the full person dork set.

    Args:
        query: A single raw query. Ignored when ``person`` or ``handle`` is set.
        person: Full name — triggers dork mode across every social platform.
        handle: Known username, searched alongside the name.
        extra: Disambiguating terms (employer, city, university).
        engines: Engine subset; None = all available.
        count: Results per engine per query.
        max_queries: Cap on dork queries executed (4 run concurrently).
        timeout: Per-query wall-clock budget.

    Returns:
        ``{"mode","queries","results","by_platform","engines_used",
        "engines_down","next_steps"}``.

    Raises:
        ValueError: If nothing to search for was given.
    """
    if not (query or person or handle):
        raise ValueError("give a query, --person, or --handle")

    queries = ([query] if query and not (person or handle)
               else person_dorks(person, handle=handle, extra=extra)[:max_queries])

    all_results: dict[str, dict] = {}
    used: set[str] = set()
    down: dict[str, str] = {}
    per_query: list[dict] = []

    # Queries are independent, so run several at once. Serially, a 10-query dork
    # set with a 45s budget each could take over five minutes — almost all of it
    # spent waiting. Concurrency is kept modest (4) because every query hits the
    # same engines, and hammering them is how you get rate-limited.
    log(f"[*] {len(queries)} queries across "
        f"{len(engines or ENGINES)} engines, 4 at a time ...")
    per_q = {q: (lambda query=q: search(query, engines=engines, count=count,
                                        timeout=timeout))
             for q in queries}
    got, q_down = fetch.gather(per_q, workers=4, timeout=timeout * 3)

    for q in queries:
        res = got.get(q)
        if not res:
            per_query.append({"query": q, "hits": 0, "engines": [],
                              "error": q_down.get(q, "no results")})
            continue
        used.update(res["engines_used"])
        down.update(res["engines_down"])
        per_query.append({"query": q, "hits": len(res["results"]),
                          "engines": res["engines_used"]})
        for r in res["results"]:
            key = r["url"].rstrip("/")
            cur = all_results.get(key)
            if cur:
                cur["queries"] = sorted(set(cur["queries"] + [q]))
                cur["engines"] = sorted(set(cur["engines"] + r["engines"]))
                cur["agreement"] = len(cur["engines"])
            else:
                all_results[key] = {**r, "queries": [q]}

    results = sorted(all_results.values(),
                     key=lambda r: (-r["agreement"], r["best_rank"], r["url"]))

    by_platform: dict[str, list[dict]] = {}
    for r in results:
        host = up.urlparse(r["url"]).netloc.lower().removeprefix("www.")
        platform = next((p for p, s in SOCIAL_SITES
                         if s.split(" OR ")[0].split("/")[0] in host), "")
        if platform:
            by_platform.setdefault(platform, []).append(r)

    steps = [
        "Results found by several engines (high `agreement`) are the real ones; "
        "single-engine hits are often stale index entries.",
        "Run osint.profile on any promising URL to pull structured identity data.",
        "Too many hits? Re-run with --extra '\"employer\" OR \"city\"' to "
        "disambiguate a common name.",
        "No hits for a platform doesn't mean no account — it means the profile "
        "isn't indexed. Open the site URL directly.",
    ]
    if down:
        steps.append(f"Engines down this run: {', '.join(sorted(down))} — retry "
                     "later, the mix changes constantly.")
    return {"mode": "person" if (person or handle) else "query",
            "person": person, "handle": handle, "queries": per_query,
            "results": results, "by_platform": by_platform,
            "engines_used": sorted(used), "engines_down": down,
            "total_unique": len(results), "next_steps": steps}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# websearch [{res['mode']}]  {res['total_unique']} unique URLs from "
             f"{len(res['engines_used'])} engines"]
    lines.append(f"# engines up: {', '.join(res['engines_used']) or 'none'}")
    if res["engines_down"]:
        lines.append(f"# engines down: {', '.join(sorted(res['engines_down']))}")
    lines.append(f"# queries run: {len(res['queries'])}")

    if res["by_platform"]:
        lines.append("## SOCIAL PROFILES FOUND (by platform)")
        for platform, hits in sorted(res["by_platform"].items()):
            for h in hits[:5]:
                lines.append(f"  {platform:<14} {h['url']}")
                if h["title"]:
                    lines.append(f"  {'':<14}   {h['title'][:110]}")

    lines.append(f"## ALL RESULTS ({len(res['results'])}, most-agreed first)")
    for r in res["results"][:80]:
        lines.append(f"  [{r['agreement']}x] {r['url']}")
        if r["title"]:
            lines.append(f"        {r['title'][:120]}")
        if r["snippet"]:
            lines.append(f"        {r['snippet'][:200]}")
    if len(res["results"]) > 80:
        lines.append(f"  ... (+{len(res['results']) - 80} more; use --json for all)")
    lines.append("## NEXT")
    lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.websearch",
        description="Query many search engines at once; merge and rank by agreement.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.websearch \'"Ada Lovelace" site:github.com\'\n'
                '  python -m osint.websearch --person "Cagan Efe Calidag"\n'
                '  python -m osint.websearch --person "Ada Lovelace" '
                '--handle adalovelace --extra "Istanbul"\n'
                f'\nengines: {", ".join(ENGINES)}\n'
                'keyed engines activate when their env var is set: '
                f'{", ".join(f"{k}={v}" for k, v in KEYED_ENGINES.items())}\n'),
    )
    p.add_argument("query", nargs="?", default="", help="Raw search query.")
    p.add_argument("--person", default="", help="Full name — run the social dork set.")
    p.add_argument("--handle", default="", help="Known username to search alongside.")
    p.add_argument("--extra", default="", help="Disambiguating terms (employer, city).")
    p.add_argument("--engines", default="",
                   help=f"Comma-separated subset of: {', '.join(ENGINES)}")
    p.add_argument("--count", type=int, default=20, help="Results per engine (default 20).")
    p.add_argument("--max-queries", type=int, default=12,
                   help="Cap dork queries in --person mode (default 12).")
    p.add_argument("--timeout", type=float, default=45.0, help="Per-query budget (default 45).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.query or args.person or args.handle):
        parser.print_help(sys.stderr)
        return 2
    engines = [e.strip() for e in args.engines.split(",") if e.strip()] or None
    if engines and (bad := [e for e in engines if e not in ENGINES]):
        print(f"error: unknown engine {bad[0]!r}; pick from {', '.join(ENGINES)}",
              file=sys.stderr)
        return 1
    try:
        res = run(args.query, person=args.person, handle=args.handle, extra=args.extra,
                  engines=engines, count=args.count, max_queries=args.max_queries,
                  timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
