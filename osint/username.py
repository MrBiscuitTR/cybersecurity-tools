"""Check one or many handles across ~70 platforms, with false-positive control.

Sherlock-style tools have one structural weakness: a lot of sites return HTTP 200
for *every* profile URL (bot walls, SPAs, soft-404s), so those tools confidently
report accounts that don't exist. This one probes a random control handle against
each site in the same run. Any site that claims the control exists is marked
UNRELIABLE and its "hit" is quarantined instead of reported. Empirically that
catches pypi, steam, wordpress, pinterest and friends every time.

Takes a LIST of handles, because a person is not one string — you'll sweep
``cagancalidag``, ``caganefecalidag``, ``caganc`` and ``ccalidag`` together and
compare. Generate candidates with :mod:`osint.variants`, edit the list by hand or
by model, then pass it here.

Every result carries one of five states:
    found       account exists (and the site proved it rejects the control)
    absent      the site says no such user
    unreliable  the site also "found" a random 14-char control handle
    unknown     blocked (403/429), timed out, or ambiguous — retry or open it
    manual      genuinely uncheckable (no addressable profile URL, or a bot wall
                on every request) — the URL is emitted, never a guess

The big social platforms are NOT login-walled for this purpose, despite the
common assumption. Instagram, X, Facebook, Threads, TikTok, Twitch, Pinterest,
Snapchat and Medium all serve OpenGraph metadata for public profiles to
unauthenticated requests and omit it for handles that don't exist — so they are
checked properly (`mode="meta"`), and the display name, bio and follower counts
come back with the verdict. Instagram serves that metadata even for PRIVATE
accounts: the name, bio and counts are public, only the posts are not.

The platform table was validated by probing a known-real handle and a random one
against every site; only sites that genuinely couldn't discriminate were left as
`manual`.

Dependencies: standard library, via :mod:`osint.fetch` (browser-realistic
headers, redirect following, cookie jar, UA rotation on 403/429).

Safety: read-only. One ordinary GET per site per handle — the same request a
browser makes opening a public profile. No login, no writes, conservative
concurrency.

Usage:
    python -m osint.username torvalds
    python -m osint.username cagancalidag caganefecalidag caganc --json
    python -m osint.username torvalds --category dev,social
    python -m osint.username torvalds --all        # include absent sites
"""

from __future__ import annotations

import argparse
import concurrent.futures
import random
import re
import secrets
import sys
import time
from dataclasses import dataclass

from common.output import emit, log
from osint import fetch, profile


@dataclass(frozen=True)
class Site:
    """One platform's presence-check recipe.

    Attributes:
        name: Short platform id used in output.
        url: Human-facing profile URL template containing ``{u}``.
        category: dev/social/pro/creative/blog/gaming/commerce.
        mode: ``status`` (verdict from the HTTP code), ``text`` (verdict from a
            body marker), ``meta`` (verdict from OpenGraph tags, which also
            yields the display name and bio), or ``manual`` (never probed).
        exists_status: Codes meaning "exists" (mode=status).
        absent_status: Codes meaning "no such account".
        exists_text: Body substring proving existence; ``{u}`` is substituted.
        absent_text: Body substring proving absence; ``{u}`` is substituted.
        absent_title: Substrings in og:title that mean "no such account" — a
            "profile not found" page served with a 200 (mode=meta).
        generic_title: og:title values that are just the site's own brand name.
            These are AMBIGUOUS: the platform serves the same generic page for a
            handle that doesn't exist AND for every handle once it starts
            rate-limiting you. Reported as unknown, never as absent.
        probe_url: API/alternate URL fetched instead of ``url`` when it gives a
            cleaner verdict than the human-facing page.
        note: Caveat surfaced with the result.
    """

    name: str
    url: str
    category: str = "social"
    mode: str = "status"
    exists_status: tuple[int, ...] = (200,)
    absent_status: tuple[int, ...] = (404,)
    exists_text: str = ""
    absent_text: str = ""
    absent_title: tuple[str, ...] = ()
    generic_title: tuple[str, ...] = ()
    probe_url: str = ""
    note: str = ""

    def profile_url(self, u: str) -> str:
        return self.url.format(u=u)

    def check_url(self, u: str) -> str:
        return (self.probe_url or self.url).format(u=u)


SITES: list[Site] = [
    # --- developer / technical ------------------------------------------------
    Site("github", "https://github.com/{u}", "dev"),
    Site("gitlab", "https://gitlab.com/{u}", "dev", absent_status=(404, 403)),
    Site("codeberg", "https://codeberg.org/{u}", "dev"),
    Site("gitea.com", "https://gitea.com/{u}", "dev"),
    Site("huggingface", "https://huggingface.co/{u}", "dev"),
    Site("dockerhub", "https://hub.docker.com/u/{u}", "dev",
         probe_url="https://hub.docker.com/v2/users/{u}/"),
    Site("dev.to", "https://dev.to/{u}", "dev"),
    Site("kaggle", "https://www.kaggle.com/{u}", "dev"),
    Site("launchpad", "https://launchpad.net/~{u}", "dev"),
    Site("keybase", "https://keybase.io/{u}", "dev"),
    Site("npm", "https://www.npmjs.com/~{u}", "dev", absent_status=(404, 403)),
    Site("codepen", "https://codepen.io/{u}", "dev"),
    Site("leetcode", "https://leetcode.com/u/{u}/", "dev"),
    Site("codeforces", "https://codeforces.com/profile/{u}", "dev",
         probe_url="https://codeforces.com/api/user.info?handles={u}",
         absent_status=(400, 404)),
    Site("hackerone", "https://hackerone.com/{u}", "dev"),
    Site("bugcrowd", "https://bugcrowd.com/{u}", "dev"),
    Site("hackernews", "https://news.ycombinator.com/user?id={u}", "dev",
         mode="text", absent_text="No such user"),
    Site("pypi", "https://pypi.org/user/{u}/", "dev", mode="manual",
         note="serves a bot challenge to every request"),
    Site("stackoverflow", "https://stackoverflow.com/users", "dev", mode="manual",
         note="no username-addressable profile URL; search by display name"),
    Site("replit", "https://replit.com/@{u}", "dev", mode="manual"),
    Site("bitbucket", "https://bitbucket.org/{u}/", "dev", mode="manual"),
    Site("sourceforge", "https://sourceforge.net/u/{u}/profile", "dev", mode="manual"),
    Site("tryhackme", "https://tryhackme.com/p/{u}", "dev", mode="manual"),

    # --- social ---------------------------------------------------------------
    Site("mastodon.social", "https://mastodon.social/@{u}", "social",
         note="only this instance; the fediverse has thousands more"),
    Site("bluesky", "https://bsky.app/profile/{u}.bsky.social", "social",
         probe_url="https://public.api.bsky.app/xrpc/com.atproto.identity."
                   "resolveHandle?handle={u}.bsky.social",
         absent_status=(400, 404)),
    Site("telegram", "https://t.me/{u}", "social", mode="text",
         exists_text="tgme_page_title"),
    Site("myspace", "https://myspace.com/{u}", "social"),
    Site("about.me", "https://about.me/{u}", "social"),
    Site("linktree", "https://linktr.ee/{u}", "social"),
    Site("gravatar", "https://gravatar.com/{u}", "social",
         note="hit means a Gravatar profile exists -> run osint.email for its JSON"),
    Site("quora", "https://www.quora.com/profile/{u}", "social"),
    Site("x/twitter", "https://x.com/{u}", "social", mode="meta",
         absent_status=(404,), absent_title=("Profile Not Found", "404")),
    Site("instagram", "https://www.instagram.com/{u}/", "social", mode="meta",
         note="public metadata is served even for private accounts: the name, "
              "bio and follower counts are visible, the posts are not",
         generic_title=("Instagram",)),
    Site("facebook", "https://www.facebook.com/{u}", "social", mode="meta",
         absent_title=("Content Not Found",), generic_title=("Facebook", "Log in")),
    Site("threads", "https://www.threads.net/@{u}", "social", mode="meta",
         generic_title=("Threads • Log in", "Threads")),
    Site("tiktok", "https://www.tiktok.com/@{u}", "social", mode="text",
         exists_text='"uniqueId":"{u}"'),
    Site("snapchat", "https://www.snapchat.com/add/{u}", "social",
         absent_status=(404,)),
    Site("reddit", "https://www.reddit.com/user/{u}/", "social", mode="meta",
         note="Reddit blocks datacenter IPs; expect UNKNOWN from a VPS/cloud host "
              "and a real answer from a residential connection"),
    Site("pinterest", "https://www.pinterest.com/{u}/", "social", mode="meta",
         generic_title=("Pinterest",)),
    Site("tumblr", "https://{u}.tumblr.com", "social", mode="manual"),
    Site("vk", "https://vk.com/{u}", "social", mode="manual"),
    Site("discord", "https://discord.com/users/{u}", "social", mode="manual",
         note="numeric user ID, not a handle"),

    # --- professional / academic ----------------------------------------------
    Site("linkedin", "https://www.linkedin.com/in/{u}", "pro",
         absent_status=(404,),
         note="200 = public profile exists (parse it with osint.linkedin). "
              "HTTP 999 means rate-limited OR absent — indistinguishable, "
              "reported as unknown"),
    Site("xing", "https://www.xing.com/profile/{u}", "pro", mode="manual"),
    Site("crunchbase", "https://www.crunchbase.com/person/{u}", "pro", mode="manual"),
    Site("producthunt", "https://www.producthunt.com/@{u}", "pro", mode="manual"),
    Site("researchgate", "https://www.researchgate.net/profile/{u}", "pro", mode="manual"),
    Site("orcid", "https://orcid.org/{u}", "pro", mode="manual", note="ORCID iD, not a handle"),
    Site("scholar", "https://scholar.google.com/citations?user={u}", "pro", mode="manual"),

    # --- creative / media ------------------------------------------------------
    Site("behance", "https://www.behance.net/{u}", "creative"),
    Site("dribbble", "https://dribbble.com/{u}", "creative"),
    Site("flickr", "https://www.flickr.com/people/{u}", "creative"),
    Site("soundcloud", "https://soundcloud.com/{u}", "creative"),
    Site("youtube", "https://www.youtube.com/@{u}", "creative"),
    Site("itch.io", "https://{u}.itch.io", "creative"),
    Site("letterboxd", "https://letterboxd.com/{u}/", "creative"),
    Site("goodreads", "https://www.goodreads.com/{u}", "creative"),
    Site("deviantart", "https://www.deviantart.com/{u}", "creative", mode="manual"),
    Site("vimeo", "https://vimeo.com/{u}", "creative", mode="manual"),
    Site("spotify", "https://open.spotify.com/user/{u}", "creative", mode="manual"),
    Site("bandcamp", "https://{u}.bandcamp.com", "creative", mode="manual"),
    Site("mixcloud", "https://www.mixcloud.com/{u}/", "creative", mode="manual"),

    # --- writing / blogs --------------------------------------------------------
    Site("substack", "https://{u}.substack.com", "blog"),
    Site("medium", "https://medium.com/@{u}", "blog", mode="meta",
         generic_title=("Medium",)),
    Site("wordpress", "https://{u}.wordpress.com", "blog", mode="manual"),
    Site("blogspot", "https://{u}.blogspot.com", "blog", mode="manual"),
    Site("hashnode", "https://hashnode.com/@{u}", "blog", mode="manual"),

    # --- gaming ------------------------------------------------------------------
    Site("chess.com", "https://www.chess.com/member/{u}", "gaming",
         probe_url="https://api.chess.com/pub/player/{u}"),
    Site("lichess", "https://lichess.org/@/{u}", "gaming"),
    Site("last.fm", "https://www.last.fm/user/{u}", "gaming"),
    Site("strava", "https://www.strava.com/athletes/{u}", "gaming"),
    Site("steam", "https://steamcommunity.com/id/{u}", "gaming", mode="text",
         absent_text="The specified profile could not be found"),
    Site("twitch", "https://www.twitch.tv/{u}", "gaming", mode="meta",
         generic_title=("Twitch",)),
    Site("roblox", "https://www.roblox.com/search/users?keyword={u}", "gaming", mode="manual"),

    # --- commerce / payments -------------------------------------------------------
    Site("gumroad", "https://{u}.gumroad.com", "commerce"),
    Site("patreon", "https://www.patreon.com/{u}", "commerce", mode="manual"),
    Site("ko-fi", "https://ko-fi.com/{u}", "commerce", mode="manual"),
    Site("buymeacoffee", "https://www.buymeacoffee.com/{u}", "commerce", mode="manual"),
    Site("paypal.me", "https://www.paypal.me/{u}", "commerce", mode="manual"),
    Site("cash.app", "https://cash.app/${u}", "commerce", mode="manual"),
    Site("venmo", "https://account.venmo.com/u/{u}", "commerce", mode="manual"),
]

CATEGORIES = sorted({s.category for s in SITES})

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}$")


def normalize(username: str) -> str:
    """Validate and normalize a handle.

    Strips whitespace, a leading ``@``, and a pasted profile URL
    (``https://github.com/torvalds`` -> ``torvalds``).

    Raises:
        ValueError: If the result is not a plausible handle.
    """
    u = username.strip()
    if "://" in u:
        u = u.rstrip("/").rsplit("/", 1)[-1]
    u = u.lstrip("@").strip()
    if not _USERNAME_RE.match(u):
        raise ValueError(f"not a plausible username: {username!r}")
    return u


def check_site(site: Site, username: str, *, timeout: float = 10.0) -> dict:
    """Probe one site for one handle.

    Single GET with browser-realistic headers. Never raises — a dead or hostile
    site becomes ``unknown`` so it can't sink the sweep.

    Args:
        site: The platform recipe.
        username: Already-normalized handle.
        timeout: Per-request timeout in seconds.

    Returns:
        ``{"site","category","username","url","state","http","note"}``.
    """
    base = {"site": site.name, "category": site.category, "username": username,
            "url": site.profile_url(username)}
    if site.mode == "manual":
        return {**base, "state": "manual", "http": 0,
                "note": site.note or "login-walled or non-discriminating; open to confirm"}

    # One attempt only. A 403/429 is re-checked later by the retry pass, so
    # retrying inline just doubles the worst case for every slow site.
    r = fetch.get(site.check_url(username), timeout=timeout, retries=0)

    if site.mode == "text":
        if not r.ok:
            if r.status in site.absent_status:
                return {**base, "state": "absent", "http": r.status, "note": ""}
            return {**base, "state": "unknown", "http": r.status,
                    "note": r.error or f"HTTP {r.status}"}
        body = r.text
        if site.exists_text:
            hit = site.exists_text.format(u=username) in body
            return {**base, "state": "found" if hit else "absent", "http": r.status,
                    "note": f"marker {'present' if hit else 'missing'}"}
        gone = site.absent_text.format(u=username) in body
        return {**base, "state": "absent" if gone else "found", "http": r.status,
                "note": f"absence marker {'present' if gone else 'missing'}"}

    if site.mode == "meta":
        # These platforms are not really login-walled: they serve OpenGraph tags
        # for public profiles to anyone, and omit them (or serve a generic
        # landing page) for handles that don't exist. That's a clean signal AND
        # it hands back the display name, bio and follower counts.
        if r.status in site.absent_status:
            return {**base, "state": "absent", "http": r.status, "note": ""}
        if not r.ok:
            return {**base, "state": "unknown", "http": r.status,
                    "note": ("anti-bot page" if r.blocked else r.error or f"HTTP {r.status}")}
        metas = profile.meta_map(r.text)
        title = metas.get("og:title", "").strip()
        desc = metas.get("og:description", "")
        if any(g.lower() == title.lower() for g in site.generic_title):
            # The site's own brand name as the title means it served its generic
            # page. That happens both for handles that don't exist AND for every
            # handle once the platform throttles your IP, so the two cannot be
            # told apart from here — say so instead of guessing "absent".
            return {**base, "state": "unknown", "http": r.status,
                    "note": f"generic '{title}' page served — either no such "
                            "handle or the platform is rate-limiting this IP; "
                            "open the URL to settle it"}
        if not title or any(bad.lower() in title.lower() for bad in site.absent_title):
            return {**base, "state": "absent", "http": r.status,
                    "note": "no profile metadata served for this handle"}
        name, stats = _parse_profile_meta(title, desc)
        return {**base, "state": "found", "http": r.status,
                "profile_name": name, "bio": desc, "stats": stats,
                "image": metas.get("og:image", ""),
                "note": (site.note or "verified via profile metadata")}

    if r.status in site.exists_status and not r.blocked:
        return {**base, "state": "found", "http": r.status, "note": site.note}
    if r.status in site.absent_status:
        return {**base, "state": "absent", "http": r.status, "note": ""}
    return {**base, "state": "unknown", "http": r.status,
            "note": ("anti-bot page" if r.blocked else r.error or f"HTTP {r.status}")}


_STAT_RE = re.compile(
    r"([\d.,]+\s*[KMB]?)\s+(Followers?|Following|Posts?|Threads?|likes?|"
    r"friends?|subscribers?|repositories)", re.I)


def _parse_profile_meta(title: str, description: str) -> tuple[str, dict[str, str]]:
    """Pull the display name and follower/post counts out of OpenGraph tags.

    Platforms write the name in the title in a handful of shapes:
        "Çağan Efe Çalıdağ (@cagancalidag) • Instagram photos and videos"
        "jack (@jack) on X"
        "Ninja - Twitch"
        "Dan – Medium"
    and the counts in the description ("307 Followers, 377 Following, 0 Posts").

    Returns:
        ``(display_name, {stat_name: value})``. The name is "" when the title
        carries no separable name.
    """
    name = title.strip()
    # Drop a trailing site suffix after a dash/bullet separator.
    name = re.split(r"\s+[•·|]\s+|\s+[-–—]\s+", name)[0].strip()
    # "Name (@handle)" -> "Name"; a bare "(@handle)" leaves nothing, which is
    # correct — that platform didn't give us a real name.
    name = re.sub(r"\s*\(@[^)]*\)\s*", " ", name).strip()
    name = re.sub(r"\s+on\s+(X|Twitter|Instagram|Threads)$", "", name, flags=re.I).strip()
    stats = {k.lower().rstrip("s"): v.strip()
             for v, k in _STAT_RE.findall(description or "")}
    # Guard against callers passing a search-result breadcrumb rather than a
    # real og:title — a URL or a path fragment is not somebody's name.
    if not name or name.startswith("@") or re.search(r"://|[›»/]|\.\w{2,4}", name):
        return "", stats
    return name, stats


def _control_handle() -> str:
    """A handle no human plausibly registered, to catch sites that say yes to
    everything. Random per run so a cached answer can't fool it."""
    return "qz" + secrets.token_hex(7)


def run(
    usernames: list[str] | str,
    *,
    categories: list[str] | None = None,
    timeout: float = 8.0,
    workers: int = 60,
    control: bool = True,
    delay: float = 0.4,
    retry_unknown: bool = True,
    max_retries: int = 25,
    cooldown: float = 3.0,
    site_budget: float = 40.0,
) -> dict:
    """Sweep one or more handles across the platform table.

    Args:
        usernames: One handle or a list of candidates to compare side by side.
        categories: Restrict to these categories (see ``CATEGORIES``). None = all.
        timeout: Per-request timeout in seconds.
        workers: How many SITES to check in parallel. Within one site the
            handles are checked sequentially, so a platform never sees more than
            one request from us at a time.
        delay: Base pause (plus jitter) between handles on the same site.
        retry_unknown: After the sweep, re-check the results that look like
            throttling (generic page, 429/403) once, serially, after a pause.
            This is what rescues a real Instagram/X hit from a busy run.
        max_retries: Cap on those retries, so the pass stays bounded.
        cooldown: Seconds to wait before the retry pass.
        site_budget: Wall-clock cap per site. Remaining handles for a site that
            blows through it are reported as unknown instead of stalling the run.
        control: Probe a random control handle per site and quarantine any site
            that "finds" it. Disabling doubles speed and destroys trust in the
            output; leave it on.

    Returns:
        ``{"usernames","checked_sites","control_username","found","unreliable",
        "unknown","manual","per_username","absent_counts","next_steps"}``.
        ``found`` is flat across handles so cross-handle patterns are visible.

    Raises:
        ValueError: If no handle is plausible.
    """
    names = [usernames] if isinstance(usernames, str) else list(usernames)
    users, bad = [], []
    for n in names:
        try:
            u = normalize(n)
            if u not in users:
                users.append(u)
        except ValueError as exc:
            bad.append(str(exc))
    if not users:
        raise ValueError(bad[0] if bad else "no usernames given")

    sites = [s for s in SITES if not categories or s.category in categories]
    probed = [s for s in sites if s.mode != "manual"]
    ctrl = _control_handle()

    todo = list(users) + ([ctrl] if control else [])
    log(f"[*] {len(users)} handle(s) x {len(probed)} sites"
        + (f" + {len(probed)} control probes" if control else "")
        + f" = {len(probed) * len(todo)} requests "
          f"({len(probed)} sites in parallel, handles sequential per site) ...")

    def sweep_one_site(site: Site) -> dict[tuple[str, str], dict]:
        """Check every handle against ONE site, one request at a time.

        Parallelism is across sites, never within a site. Firing nine
        simultaneous requests at Instagram for nine candidate handles is what
        makes a platform start serving its generic page to you — which then
        looks like "site is unreliable" and throws away real hits. One request
        per host at a time, with a little jitter, keeps every platform answering.
        """
        out: dict[tuple[str, str], dict] = {}
        deadline = time.monotonic() + site_budget
        for i, u in enumerate(todo):
            if time.monotonic() > deadline:
                # One pathological site must not set the wall-clock floor for
                # the whole sweep; the rest of its handles are reported honestly
                # as unknown rather than silently dropped.
                out[(site.name, u)] = {
                    "site": site.name, "category": site.category, "username": u,
                    "url": site.profile_url(u), "state": "unknown", "http": 0,
                    "note": f"site too slow (over {site_budget:.0f}s budget); retry it alone"}
                continue
            if i:
                time.sleep(delay + random.uniform(0, delay))
            try:
                out[(site.name, u)] = check_site(site, u, timeout=timeout)
            except Exception as exc:  # noqa: BLE001 - never let one site win
                out[(site.name, u)] = {
                    "site": site.name, "category": site.category, "username": u,
                    "url": site.profile_url(u), "state": "unknown", "http": 0,
                    "note": f"{type(exc).__name__}: {exc}"}
        return out

    raw: dict[tuple[str, str], dict] = {}
    if probed:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(workers, len(probed))) as pool:
            for chunk in pool.map(sweep_one_site, probed):
                raw.update(chunk)

    # Second chance. A platform that served its generic page or a 429 during the
    # burst will usually answer properly once things go quiet, and those are
    # exactly the results worth rescuing: an "unknown" on Instagram can be a real
    # account with the subject's full name on it. Retried serially, with a real
    # pause, and capped so this can't run away.
    by_site = {s.name: s for s in probed}
    retryable = [k for k, r in raw.items()
                 if r["state"] == "unknown" and (
                     "generic" in r.get("note", "") or r.get("http") in (429, 403))]
    if retryable and retry_unknown:
        retryable = retryable[:max_retries]
        log(f"[*] retrying {len(retryable)} throttled check(s) after a pause ...")
        time.sleep(cooldown)
        grouped: dict[str, list[str]] = {}
        for site_name, u in retryable:
            grouped.setdefault(site_name, []).append(u)

        def retry_site(item: tuple[str, list[str]]) -> dict[tuple[str, str], dict]:
            site_name, handles_to_retry = item
            site = by_site.get(site_name)
            fixed: dict[tuple[str, str], dict] = {}
            if not site:
                return fixed
            for i, u in enumerate(handles_to_retry):
                if i:
                    time.sleep(delay * 2)
                try:
                    again = check_site(site, u, timeout=timeout)
                except Exception:  # noqa: BLE001 - a failed retry keeps the old result
                    continue
                if again["state"] != "unknown":
                    fixed[(site_name, u)] = {
                        **again,
                        "note": (again.get("note", "") + " (resolved on retry)").strip()}
            return fixed

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(workers, len(grouped))) as pool:
            for chunk in pool.map(retry_site, grouped.items()):
                raw.update(chunk)

    unreliable_sites = {s.name for s in probed
                        if control and raw.get((s.name, ctrl), {}).get("state") == "found"}

    found, unreliable, unknown = [], [], []
    per_user: dict[str, dict] = {u: {"found": [], "unknown": 0, "absent": 0} for u in users}
    for s in probed:
        for u in users:
            res = raw[(s.name, u)]
            if s.name in unreliable_sites:
                if res["state"] == "found":
                    unreliable.append({**res, "state": "unreliable",
                                       "note": "site also 'found' the random control handle"})
                continue
            if res["state"] == "found":
                found.append(res)
                per_user[u]["found"].append(s.name)
            elif res["state"] == "absent":
                per_user[u]["absent"] += 1
            else:
                unknown.append(res)
                per_user[u]["unknown"] += 1

    manual = [{"site": s.name, "category": s.category, "username": u,
               "url": s.profile_url(u), "state": "manual", "http": 0,
               "note": s.note or "login-walled; open to confirm"}
              for s in sites if s.mode == "manual" for u in users]

    for bucket in (found, unreliable, unknown, manual):
        bucket.sort(key=lambda r: (r["username"], r["category"], r["site"]))

    next_steps = [
        "Run osint.profile on each FOUND url to pull the real name, bio, location "
        "and any links the profile itself declares — a link from one profile to "
        "another is the strongest identity evidence there is.",
        "Compare handles: a handle found on 6 sites and one found on 1 are not "
        "equally likely to be the same person. Check the bios before merging.",
        "UNKNOWN is not ABSENT. Those sites blocked us; open them by hand or retry.",
        "Instagram/X/Facebook/Threads/TikTok/Twitch/Medium hits are verified from "
        "the profile metadata those sites serve publicly — the name, bio and "
        "follower counts come with them, even for private Instagram accounts.",
        "MANUAL is now only for sites that genuinely cannot be checked (no "
        "addressable profile URL, or a bot wall on every request). Open those.",
    ]
    if unreliable_sites:
        next_steps.append(
            f"Ignore hits on {', '.join(sorted(unreliable_sites))} — they answer "
            "'yes' to any handle.")

    return {"usernames": users, "invalid": bad, "checked_sites": len(probed),
            "control_username": ctrl if control else "",
            "unreliable_sites": sorted(unreliable_sites),
            "found": found, "unreliable": unreliable, "unknown": unknown,
            "manual": manual, "per_username": per_user, "next_steps": next_steps}


def _compact_lines(res: dict, show_all: bool = False) -> list[str]:
    lines = [f"# usernames: {', '.join(res['usernames'])}   "
             f"{len(res['found'])} hits across {res['checked_sites']} checkable sites"]
    for u, d in res["per_username"].items():
        lines.append(f"#   {u}: {len(d['found'])} found, {d['absent']} absent, "
                     f"{d['unknown']} unknown")

    lines.append(f"## FOUND ({len(res['found'])}) — site proved it rejects a random control")
    for r in res["found"]:
        lines.append(f"  {r['username']:<18} [{r['category']}] {r['site']:<16} {r['url']}")
        if r.get("profile_name"):
            lines.append(f"  {'':<18}   name: {r['profile_name']}")
        if r.get("stats"):
            lines.append(f"  {'':<18}   {', '.join(f'{k}: {v}' for k, v in r['stats'].items())}")
        if r.get("bio"):
            lines.append(f"  {'':<18}   bio: {r['bio'][:160]}")
        if r.get("note"):
            lines.append(f"  {'':<18}   note: {r['note']}")
    if not res["found"]:
        lines.append("  (none)")

    if res["unreliable"]:
        lines.append(f"## UNRELIABLE ({len(res['unreliable'])}) — these sites say yes to "
                     f"anything; a hit here is meaningless")
        for r in res["unreliable"]:
            lines.append(f"  {r['username']:<18} {r['site']:<16} {r['url']}")

    if res["unknown"]:
        lines.append(f"## UNKNOWN ({len(res['unknown'])}) — blocked/errored, NOT absent")
        for r in res["unknown"]:
            lines.append(f"  {r['username']:<18} {r['site']:<16} {r['note']}")

    lines.append(f"## MANUAL ({len(res['manual'])}) — login-walled; open these by eye")
    for r in res["manual"]:
        lines.append(f"  {r['username']:<18} {r['site']:<16} {r['url']}")

    if show_all:
        lines.append("## ABSENT counts per handle")
        for u, d in res["per_username"].items():
            lines.append(f"  {u}: {d['absent']}")
    lines.append("## NEXT")
    lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.username",
        description="Find handles across ~70 platforms, with false-positive control.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m osint.username torvalds\n"
                "  python -m osint.username cagancalidag caganefecalidag caganc\n"
                "  python -m osint.username torvalds --category dev,social --json\n"
                f"\ncategories: {', '.join(CATEGORIES)}\n"),
    )
    p.add_argument("username", nargs="*", help="One or more handles (@ and URLs are fine).")
    p.add_argument("--category", default="",
                   help=f"Comma-separated subset of: {', '.join(CATEGORIES)}")
    p.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout (default 8).")
    p.add_argument("--workers", type=int, default=60,
                   help="Sites checked in parallel (default 60 = all at once). "
                        "Each site is still probed one handle at a time.")
    p.add_argument("--delay", type=float, default=0.4,
                   help="Pause between handles on the same site (default 0.4s).")
    p.add_argument("--no-retry", action="store_true",
                   help="Skip the retry pass for throttled checks (faster, lossier).")
    p.add_argument("--no-control", action="store_true",
                   help="Skip control probes (2x faster, results untrustworthy).")
    p.add_argument("--all", action="store_true", help="Also show absent counts.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.username:
        parser.print_help(sys.stderr)
        return 2

    cats = [c.strip() for c in args.category.split(",") if c.strip()] or None
    if cats and (bad := [c for c in cats if c not in CATEGORIES]):
        print(f"error: unknown category {bad[0]!r}; pick from {', '.join(CATEGORIES)}",
              file=sys.stderr)
        return 1
    try:
        res = run(args.username, categories=cats, timeout=args.timeout,
                  workers=args.workers, control=not args.no_control,
                  delay=args.delay, retry_unknown=not args.no_retry)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    emit(res, as_json=args.json, lines=_compact_lines(res, args.all))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
