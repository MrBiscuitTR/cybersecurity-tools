"""Everything GitHub publishes about an account — including the author's email.

GitHub is the highest-yield single platform in person OSINT, and not because of
the profile page. Every public commit carries the author's configured email in
its metadata, and the API serves it to anyone. A developer who has never written
their address anywhere has usually pushed it to a public repository hundreds of
times.

What this collects:

    profile      name, bio, company, location, blog/website, X handle, hireable,
                 join date, follower counts — the profile API returns a dozen
                 fields the HTML page never shows in one place
    emails       author addresses from recent commits across the account's
                 repositories. Two kinds come back and they are not equal:
                   real      e.g. someone@gmail.com — their actual address
                   noreply   ID+login@users.noreply.github.com — GitHub's
                             privacy proxy. Not reachable, but the numeric ID
                             is a permanent account identifier that survives
                             renames, which is its own useful pivot.
    orgs         organizations the account belongs to publicly
    repos        recent repositories with languages and topics, which double as
                 a decent read on what the person actually works on

Rate limits: unauthenticated the API allows 60 requests/hour, which this budget
respects by capping repositories inspected. Set ``$GITHUB_TOKEN`` for 5000/hour
and noticeably better results — that is the single most useful key for this tool.

External API: https://api.github.com (free; token optional but recommended).

Safety: read-only. Reads public API endpoints only. No writes, no auth beyond an
optional read token, nothing private.

Usage:
    python -m osint.github torvalds
    python -m osint.github MrBiscuitTR --json
    python -m osint.github torvalds --max-repos 10
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from common.output import emit, log
from osint import fetch

_API = "https://api.github.com"
_NOREPLY_RE = re.compile(r"^(\d+)\+(.+)@users\.noreply\.github\.com$", re.I)


# Service accounts that commit on a human's behalf. Their addresses are real
# addresses, just not the subject's.
_BOT_RE = re.compile(
    r"(?i)\[bot\]|^(?:actions|github-actions|noreply|no-reply|support|"
    r"dependabot|renovate|greenkeeper|semantic-release|netlify|vercel|"
    r"copilot)[@\[]|@(?:bots?\.|dependabot\.)")


def _is_bot_address(email: str, name: str = "") -> bool:
    """True if this commit identity is automation rather than a person."""
    if _BOT_RE.search(email) or _BOT_RE.search(name or ""):
        return True
    return email in {"noreply@github.com", "action@github.com"}


def _headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28"}
    if token := os.environ.get("GITHUB_TOKEN", ""):
        h["Authorization"] = f"Bearer {token}"
    return h


def profile(login: str, *, timeout: float = 20.0) -> dict:
    """Fetch the public profile fields for one account."""
    data, r = fetch.get_json(f"{_API}/users/{login}", headers=_headers(),
                             timeout=timeout)
    if not isinstance(data, dict) or not data.get("login"):
        return {"error": f"HTTP {r.status}" if r else "no data"}
    return {k: data.get(k) for k in (
        "login", "id", "name", "company", "blog", "location", "email", "bio",
        "twitter_username", "public_repos", "public_gists", "followers",
        "following", "created_at", "updated_at", "hireable", "type",
        "avatar_url", "html_url") if data.get(k) not in (None, "")}


def commit_emails(login: str, *, max_repos: int = 8, per_repo: int = 15,
                  timeout: float = 20.0) -> dict:
    """Harvest author emails from an account's public commit metadata.

    Args:
        login: GitHub username.
        max_repos: Repositories to inspect, most recently pushed first. Each one
            costs an API call, and unauthenticated callers only get 60/hour.
        per_repo: Commits to read per repository.
        timeout: Per-request timeout.

    Returns:
        ``{"emails": [{"email","names","kind","repos"}], "user_id",
        "repos_checked"}``. ``kind`` is ``real`` or ``noreply``.
    """
    repos, _ = fetch.get_json(
        f"{_API}/users/{login}/repos?per_page={max_repos}&sort=pushed&type=owner",
        headers=_headers(), timeout=timeout)
    if not isinstance(repos, list) or not repos:
        return {"emails": [], "user_id": "", "repos_checked": 0}

    names = [r.get("full_name") for r in repos if r.get("full_name")][:max_repos]
    log(f"[*] github: reading commits from {len(names)} repo(s) of {login}")

    def one(full: str) -> list[dict]:
        data, _ = fetch.get_json(
            f"{_API}/repos/{full}/commits?per_page={per_repo}",
            headers=_headers(), timeout=timeout)
        out = []
        for c in data if isinstance(data, list) else []:
            commit = c.get("commit") or {}
            for role in ("author", "committer"):
                who = commit.get(role) or {}
                addr = (who.get("email") or "").strip().lower()
                # CI and web-UI commits are attributed to service accounts that
                # belong to nobody. Reporting "vercel[bot]" as the subject's
                # address is worse than reporting nothing.
                if not addr or _is_bot_address(addr, who.get("name", "")):
                    continue
                out.append({"email": addr, "name": who.get("name", ""),
                            "repo": full})
        return out

    got, _ = fetch.gather({n: (lambda full=n: one(full)) for n in names},
                          workers=5, timeout=timeout * 3)

    merged: dict[str, dict] = {}
    user_id = ""
    for hits in got.values():
        for h in hits:
            entry = merged.setdefault(h["email"], {
                "email": h["email"], "names": [], "repos": [], "kind": "real"})
            if h["name"] and h["name"] not in entry["names"]:
                entry["names"].append(h["name"])
            if h["repo"] not in entry["repos"]:
                entry["repos"].append(h["repo"])
            # Any address on the noreply domain is a privacy proxy, not a
            # reachable mailbox — only the numeric-prefixed form carries the id.
            if h["email"].endswith("@users.noreply.github.com"):
                entry["kind"] = "noreply"
                if m := _NOREPLY_RE.match(h["email"]):
                    user_id = user_id or m.group(1)

    # Real addresses first: a noreply proxy is an identifier, not a contact.
    ordered = sorted(merged.values(),
                     key=lambda e: (e["kind"] != "real", -len(e["repos"])))
    return {"emails": ordered, "user_id": user_id, "repos_checked": len(names)}


def run(login: str, *, max_repos: int = 8, timeout: float = 20.0) -> dict:
    """Collect profile, commit emails, organizations and repositories.

    Args:
        login: GitHub username.
        max_repos: Repositories to inspect for commit emails.
        timeout: Per-request timeout.

    Returns:
        ``{"login","profile","emails","user_id","orgs","repos","topics",
        "linked_accounts","next_steps"}``.

    Raises:
        ValueError: If ``login`` isn't a plausible GitHub username.
    """
    login = login.strip().lstrip("@")
    if "/" in login:
        login = login.rstrip("/").rsplit("/", 1)[-1]
    if not re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", login):
        raise ValueError(f"not a plausible GitHub username: {login!r}")

    sources = {
        "profile": lambda: profile(login, timeout=timeout),
        "commits": lambda: commit_emails(login, max_repos=max_repos, timeout=timeout),
        "orgs": lambda: fetch.get_json(f"{_API}/users/{login}/orgs",
                                       headers=_headers(), timeout=timeout)[0],
        "repos": lambda: fetch.get_json(
            f"{_API}/users/{login}/repos?per_page=30&sort=pushed",
            headers=_headers(), timeout=timeout)[0],
    }
    got, down = fetch.gather(sources, workers=4, timeout=timeout * 3)

    prof = got.get("profile", {}) or {}
    commits = got.get("commits", {}) or {}
    repos = [r for r in (got.get("repos") or []) if isinstance(r, dict)]
    orgs = [{"login": o.get("login", ""), "url": o.get("url", "")}
            for o in (got.get("orgs") or []) if isinstance(o, dict)]

    topics: list[str] = []
    for r in repos:
        for t in (r.get("topics") or []):
            if t not in topics:
                topics.append(t)
        lang = r.get("language")
        if lang and lang not in topics:
            topics.append(lang)

    # Fields the profile itself declares as other accounts.
    linked = []
    if prof.get("twitter_username"):
        linked.append({"platform": "x/twitter", "handle": prof["twitter_username"],
                       "url": f"https://x.com/{prof['twitter_username']}",
                       "declared_by": "GitHub profile field"})
    if prof.get("blog"):
        blog = prof["blog"]
        linked.append({"platform": "website", "handle": "",
                       "url": blog if blog.startswith("http") else f"https://{blog}",
                       "declared_by": "GitHub profile field"})

    real = [e for e in commits.get("emails", []) if e["kind"] == "real"]
    steps = []
    if real:
        steps.append(f"{len(real)} real address(es) from commit metadata — feed "
                     f"them to osint.email: --email {real[0]['email']}")
    if commits.get("user_id"):
        steps.append(f"Numeric account id {commits['user_id']} is permanent and "
                     "survives username changes — a durable identifier.")
    if prof.get("blog"):
        steps.append(f"Profile links a website ({prof['blog']}) — run "
                     "osint.profile on it, then osint.infra on the domain.")
    if prof.get("company"):
        steps.append(f"Company '{prof['company']}' is a disambiguator for "
                     "osint.websearch and a lead for osint.records.")
    if not real and not prof:
        steps.append("Nothing public. Check the spelling, or the account may be "
                     "new/empty. $GITHUB_TOKEN raises the rate limit a lot.")
    if not os.environ.get("GITHUB_TOKEN"):
        steps.append("Set $GITHUB_TOKEN: unauthenticated is 60 requests/hour, so "
                     "repositories get skipped on busy accounts.")

    return {"login": login, "profile": prof, "emails": commits.get("emails", []),
            "user_id": commits.get("user_id", ""), "orgs": orgs,
            "repos": [{"name": r.get("name", ""), "language": r.get("language"),
                       "topics": r.get("topics") or [],
                       "description": (r.get("description") or "")[:120],
                       "pushed_at": r.get("pushed_at", "")} for r in repos[:20]],
            "topics": topics[:40], "linked_accounts": linked,
            "sources_down": down, "next_steps": steps}


def _compact_lines(res: dict) -> list[str]:
    p = res["profile"]
    lines = [f"# github: {res['login']}"
             + (f"  (id {res['user_id']})" if res["user_id"] else "")]
    if p:
        lines.append("## PROFILE")
        for k in ("name", "bio", "company", "location", "blog", "email",
                  "twitter_username", "created_at", "followers", "public_repos"):
            if p.get(k):
                lines.append(f"  {k:<18} {str(p[k])[:150]}")
    if res["emails"]:
        lines.append(f"## EMAILS FROM COMMIT METADATA ({len(res['emails'])})")
        for e in res["emails"]:
            tag = "REAL" if e["kind"] == "real" else "noreply proxy"
            lines.append(f"  [{tag}] {e['email']}")
            if e["names"]:
                lines.append(f"           committed as: {', '.join(e['names'])}")
            lines.append(f"           in: {', '.join(e['repos'][:4])}")
    else:
        lines.append("## EMAILS FROM COMMIT METADATA (none found)")
    if res["linked_accounts"]:
        lines.append("## ACCOUNTS DECLARED ON THE PROFILE")
        for l in res["linked_accounts"]:
            lines.append(f"  {l['platform']:<12} {l['url']}")
    if res["orgs"]:
        lines.append(f"## ORGANIZATIONS ({len(res['orgs'])})")
        lines.append("  " + ", ".join(o["login"] for o in res["orgs"]))
    if res["topics"]:
        lines.append(f"## LANGUAGES / TOPICS ({len(res['topics'])})")
        lines.append("  " + ", ".join(res["topics"][:30]))
    if res["repos"]:
        lines.append(f"## RECENT REPOSITORIES ({len(res['repos'])})")
        for r in res["repos"][:10]:
            lines.append(f"  {r['name']:<28} {r['language'] or '-':<12} "
                         f"{r['description'][:60]}")
    lines.append("## NEXT")
    lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.github",
        description="GitHub account -> profile, commit-metadata emails, orgs, topics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m osint.github torvalds\n"
                "  python -m osint.github MrBiscuitTR --json\n"
                "  python -m osint.github torvalds --max-repos 15\n"
                "\nSet $GITHUB_TOKEN to raise the rate limit from 60 to 5000/hour.\n"),
    )
    p.add_argument("login", nargs="?", help="GitHub username (a profile URL is fine).")
    p.add_argument("--max-repos", type=int, default=8,
                   help="Repositories to read commits from (default 8).")
    p.add_argument("--timeout", type=float, default=20.0, help="Timeout (default 20).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.login:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(args.login, max_repos=args.max_repos, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
