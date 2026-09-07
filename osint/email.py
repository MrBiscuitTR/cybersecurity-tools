"""Everything publicly knowable about an email address, from many sources at once.

An address is the highest-value OSINT pivot there is: it is globally unique,
people reuse it for a decade, and it links accounts that share nothing else. This
module attacks it from every free angle simultaneously and merges the answers.

Sources, all queried in parallel, each optional:

    identity
      Gravatar profile JSON   gravatar.com/{sha256|md5}.json — often returns the
                              real name, bio, location AND a list of verified
                              accounts the owner attached. The single richest
                              free source for an address. Tried with both hash
                              algorithms because Gravatar migrated to SHA-256.
      Libravatar              federated Gravatar alternative, same idea
      GitHub commits          the address appears in public commit metadata,
                              which ties it to a GitHub account (uses
                              $GITHUB_TOKEN when set; unauthenticated otherwise)
      search engines          the address as a quoted phrase across ~8 engines

    exposure / breaches
      XposedOrNot             free, no auth — breach list per address
      Hudson Rock             free, no auth — infostealer-infection check
      LeakCheck public        free, no auth — breach source names
      HaveIBeenPwned          $HIBP_API_KEY (paid); used when present
      BreachDirectory         $RAPIDAPI_KEY; used when present

    deliverability / hygiene
      MX records              via the repo's privacy-first DoH resolvers
      disposable domain check against a built-in list of throwaway providers
      role-account detection  info@, admin@, sales@ — not a person

What this deliberately does NOT do: SMTP ``VRFY``/``RCPT TO`` probing to test
whether an address exists. It is unreliable (catch-all domains answer yes to
everything, greylisting answers no to everything), it is rude to the receiving
mail server, and on many networks it gets the source IP blacklisted. Address
existence is inferred from evidence here, not probed.

Safety: read-only. Queries third-party APIs and DNS about the address; never
sends mail, never connects to the target's mail server, never attempts a login.
Breach data returned is metadata (which breach, what fields) — this does not
retrieve or display passwords.

Usage:
    python -m osint.email someone@example.com
    python -m osint.email someone@example.com --json
    python -m osint.email someone@example.com --skip breaches
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse as up

from common import dns
from common.output import emit, log
from osint import fetch

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$")

# Throwaway providers — a hit here means the address was made to be discarded.
DISPOSABLE_DOMAINS = frozenset("""
mailinator.com guerrillamail.com 10minutemail.com tempmail.com temp-mail.org
throwawaymail.com yopmail.com trashmail.com sharklasers.com getnada.com
maildrop.cc dispostable.com fakeinbox.com mailnesia.com mytemp.email
spamgourmet.com mohmal.com tempr.email emailondeck.com burnermail.io
simplelogin.io anonaddy.com relay.firefox.com duck.com icloud.com.hidemyemail
""".split())

# Mailbox names that belong to a function, not a person.
ROLE_LOCALS = frozenset("""
admin administrator info contact support sales help hello team billing accounts
noreply no-reply postmaster webmaster abuse security root sysadmin office hr
jobs careers marketing press media legal privacy dpo service enquiries hi
""".split())


def normalize(address: str) -> str:
    """Validate and lowercase an address.

    Raises:
        ValueError: If it isn't a syntactically valid address.
    """
    a = address.strip().lower().lstrip("<").rstrip(">")
    if not _EMAIL_RE.match(a):
        raise ValueError(f"not a valid email address: {address!r}")
    return a


def hashes(address: str) -> dict[str, str]:
    """Gravatar-style hashes of an address (both algorithms).

    Gravatar historically keyed on MD5 and now prefers SHA-256; both still
    resolve, and a profile may exist under either. Returned so a caller can
    search for the hashes themselves — leaked databases and avatar URLs often
    contain the hash rather than the address.
    """
    canon = address.strip().lower().encode()
    return {"md5": hashlib.md5(canon).hexdigest(),  # noqa: S324 - Gravatar's scheme
            "sha256": hashlib.sha256(canon).hexdigest()}


def _gravatar(address: str, timeout: float) -> dict:
    """Gravatar profile JSON. Tries SHA-256 then MD5."""
    h = hashes(address)
    for algo in ("sha256", "md5"):
        data, _ = fetch.get_json(f"https://gravatar.com/{h[algo]}.json", timeout=timeout)
        entry = (data or {}).get("entry")
        if not entry:
            continue
        e = entry[0] if isinstance(entry, list) else entry
        name = e.get("name") or {}
        return {
            "hash_algo": algo,
            "profile_url": e.get("profileUrl", ""),
            "username": e.get("preferredUsername", ""),
            "display_name": e.get("displayName", ""),
            "full_name": (name.get("formatted") if isinstance(name, dict) else "") or "",
            "given_name": (name.get("givenName") if isinstance(name, dict) else "") or "",
            "family_name": (name.get("familyName") if isinstance(name, dict) else "") or "",
            "about": e.get("aboutMe", ""),
            "location": e.get("currentLocation", ""),
            "photo": (e.get("thumbnailUrl", "")),
            "accounts": [{"platform": a.get("shortname", a.get("domain", "")),
                          "url": a.get("url", ""), "username": a.get("username", ""),
                          "verified": bool(a.get("verified"))}
                         for a in e.get("accounts", []) or []],
            "urls": [{"title": u.get("title", ""), "url": u.get("value", "")}
                     for u in e.get("urls", []) or []],
        }
    return {}


def _libravatar(address: str, timeout: float) -> dict:
    """Libravatar avatar existence (federated Gravatar alternative)."""
    h = hashes(address)
    r = fetch.get(f"https://seccdn.libravatar.org/avatar/{h['md5']}?d=404",
                  timeout=timeout, retries=0)
    return {"avatar_exists": r.ok, "url": r.url} if r.ok else {}


def _gravatar_avatar(address: str, timeout: float) -> dict:
    """Whether an avatar image exists (weaker than the profile, but survives when
    the profile API is unavailable)."""
    h = hashes(address)
    for algo in ("sha256", "md5"):
        r = fetch.get(f"https://gravatar.com/avatar/{h[algo]}?d=404",
                      timeout=timeout, retries=0)
        if r.ok:
            return {"avatar_exists": True, "hash_algo": algo,
                    "url": f"https://gravatar.com/avatar/{h[algo]}"}
    return {}


def _xposedornot(address: str, timeout: float) -> dict:
    """XposedOrNot breach lookup (free, no auth)."""
    data, r = fetch.get_json(
        f"https://api.xposedornot.com/v1/check-email/{up.quote(address)}", timeout=timeout)
    if not isinstance(data, dict):
        return {}
    breaches = data.get("breaches") or []
    flat = breaches[0] if breaches and isinstance(breaches[0], list) else breaches
    if data.get("Error") == "Not found" or not flat:
        return {"breaches": [], "count": 0, "clean": True}
    return {"breaches": sorted({str(b) for b in flat}), "count": len(flat), "clean": False}


def _hudsonrock(address: str, timeout: float) -> dict:
    """Hudson Rock infostealer-infection check (free, no auth).

    Different question from a breach: this is 'was a machine with this address
    logged in on it infected by credential-stealing malware'.
    """
    data, _ = fetch.get_json(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={up.quote(address)}", timeout=timeout)
    if not isinstance(data, dict):
        return {}
    msg = str(data.get("message", ""))
    if "not found" in msg.lower() or "no results" in msg.lower():
        return {"infected": False, "message": msg}
    stealers = data.get("stealers") or []
    return {"infected": bool(stealers), "message": msg,
            "stealer_count": len(stealers),
            "computers": [{"date": s.get("date_compromised", ""),
                           "os": s.get("operating_system", ""),
                           "ip": s.get("ip", ""),
                           "malware": s.get("stealer_family", "")}
                          for s in stealers[:10]]}


def _leakcheck(address: str, timeout: float) -> dict:
    """LeakCheck public endpoint (free, no auth; returns source names only)."""
    data, _ = fetch.get_json(
        f"https://leakcheck.io/api/public?check={up.quote(address)}", timeout=timeout)
    if not isinstance(data, dict) or not data.get("success"):
        return {}
    return {"found": data.get("found", 0),
            "sources": [s.get("name", "") if isinstance(s, dict) else str(s)
                        for s in data.get("sources", [])]}


def _hibp(address: str, timeout: float) -> dict:
    """HaveIBeenPwned — the authoritative source, but needs a paid key."""
    key = os.environ.get("HIBP_API_KEY", "")
    if not key:
        return {}
    data, r = fetch.get_json(
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        f"{up.quote(address)}?truncateResponse=false",
        headers={"hibp-api-key": key, "User-Agent": "cybersecurity-tools-osint"},
        timeout=timeout)
    if r.status == 404:
        return {"breaches": [], "clean": True}
    if not isinstance(data, list):
        return {}
    return {"clean": False, "count": len(data),
            "breaches": [{"name": b.get("Name", ""), "date": b.get("BreachDate", ""),
                          "data": b.get("DataClasses", [])} for b in data]}


def _breachdirectory(address: str, timeout: float) -> dict:
    """BreachDirectory via RapidAPI ($RAPIDAPI_KEY), when configured."""
    key = os.environ.get("RAPIDAPI_KEY", "")
    if not key:
        return {}
    data, _ = fetch.get_json(
        f"https://breachdirectory.p.rapidapi.com/?func=auto&term={up.quote(address)}",
        headers={"X-RapidAPI-Key": key,
                 "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"}, timeout=timeout)
    if not isinstance(data, dict) or not data.get("success"):
        return {}
    return {"found": data.get("found", 0),
            "sources": sorted({r.get("sources", "") for r in data.get("result", [])
                               if isinstance(r, dict)})}


def _github(address: str, timeout: float) -> dict:
    """Find a GitHub account by commit-authoring address.

    Public commit metadata contains the author's address; GitHub's search API
    indexes it. Works far better with a token — unauthenticated search is heavily
    throttled — so $GITHUB_TOKEN is used when present.
    """
    hdrs = {"Accept": "application/vnd.github+json"}
    if tok := os.environ.get("GITHUB_TOKEN", ""):
        hdrs["Authorization"] = f"Bearer {tok}"

    out: dict = {}
    data, _ = fetch.get_json(
        f"https://api.github.com/search/users?q={up.quote(address)}+in:email",
        headers=hdrs, timeout=timeout)
    if isinstance(data, dict) and data.get("items"):
        out["users"] = [{"login": u.get("login", ""), "url": u.get("html_url", "")}
                        for u in data["items"][:10]]
    data, _ = fetch.get_json(
        f"https://api.github.com/search/commits?q=author-email:{up.quote(address)}",
        headers={**hdrs, "Accept": "application/vnd.github.cloak-preview+json"},
        timeout=timeout)
    if isinstance(data, dict) and data.get("items"):
        seen: dict[str, dict] = {}
        for c in data["items"][:30]:
            author = (c.get("author") or {}).get("login", "")
            repo = (c.get("repository") or {}).get("full_name", "")
            name = ((c.get("commit") or {}).get("author") or {}).get("name", "")
            if author or name:
                seen.setdefault(author or name, {
                    "login": author, "commit_name": name, "repos": []})
                if repo and repo not in seen[author or name]["repos"]:
                    seen[author or name]["repos"].append(repo)
        out["commit_authors"] = list(seen.values())
        out["commit_total"] = data.get("total_count", 0)
    return out


def _websearch(address: str, timeout: float) -> dict:
    """The address as a quoted phrase across every available engine."""
    from osint import websearch
    res = websearch.search(f'"{address}"', count=15, timeout=timeout)
    return {"results": [{"url": r["url"], "title": r["title"], "snippet": r["snippet"],
                         "agreement": r["agreement"]} for r in res["results"][:20]],
            "engines_used": res["engines_used"]} if res["results"] else {}


def _mx(domain: str) -> dict:
    """MX lookup over the repo's privacy-first DoH resolvers."""
    rec = dns.resolve(domain, "MX")
    hosts = [str(a.get("data", "")).split()[-1].rstrip(".")
             for a in rec.get("answers", []) if a.get("data")]
    return {"mx": sorted({h for h in hosts if h}), "rcode": rec.get("rcode_name", "")}


def run(
    address: str,
    *,
    timeout: float = 20.0,
    skip: tuple[str, ...] = (),
) -> dict:
    """Gather everything public about an email address.

    Args:
        address: The address to investigate.
        timeout: Per-source timeout in seconds.
        skip: Source groups to skip: ``identity``, ``breaches``, ``search``,
            ``dns``. Use when you want a fast partial answer.

    Returns:
        ``{"address","local","domain","hashes","classification","identity",
        "breaches","dns","search","sources_up","sources_down","next_steps"}``.

    Raises:
        ValueError: If the address is invalid.
    """
    addr = normalize(address)
    local, _, domain = addr.partition("@")

    classification = {
        "role_account": local in ROLE_LOCALS,
        "disposable": domain in DISPOSABLE_DOMAINS,
        "plus_tag": local.split("+", 1)[1] if "+" in local else "",
        "base_local": local.split("+", 1)[0],
        "looks_like_name": bool(re.match(r"^[a-z]+[._-]?[a-z]+$", local.split("+")[0])),
    }

    sources: dict[str, object] = {}
    if "identity" not in skip:
        sources["gravatar"] = lambda: _gravatar(addr, timeout)
        sources["gravatar_avatar"] = lambda: _gravatar_avatar(addr, timeout)
        sources["libravatar"] = lambda: _libravatar(addr, timeout)
        sources["github"] = lambda: _github(addr, timeout)
    if "breaches" not in skip:
        sources["xposedornot"] = lambda: _xposedornot(addr, timeout)
        sources["hudsonrock"] = lambda: _hudsonrock(addr, timeout)
        sources["leakcheck"] = lambda: _leakcheck(addr, timeout)
        sources["hibp"] = lambda: _hibp(addr, timeout)
        sources["breachdirectory"] = lambda: _breachdirectory(addr, timeout)
    if "dns" not in skip:
        sources["mx"] = lambda: _mx(domain)
    if "search" not in skip:
        sources["websearch"] = lambda: _websearch(addr, timeout + 25)

    log(f"[*] querying {len(sources)} sources for {addr} ...")
    got, down = fetch.gather(sources, workers=8, timeout=timeout * 4)  # type: ignore[arg-type]

    grav = got.get("gravatar", {}) or {}
    identity = {
        "names": sorted({n for n in [grav.get("full_name"), grav.get("display_name")] if n}),
        "usernames": sorted({u for u in [grav.get("username")] if u}
                            | {a["login"] for a in
                               (got.get("github", {}) or {}).get("users", []) if a.get("login")}
                            | {a["login"] for a in
                               (got.get("github", {}) or {}).get("commit_authors", [])
                               if a.get("login")}),
        "location": grav.get("location", ""),
        "bio": grav.get("about", ""),
        "linked_accounts": (grav.get("accounts", []) or []) + [
            {"platform": "github", "url": u["url"], "username": u["login"],
             "verified": False}
            for u in (got.get("github", {}) or {}).get("users", [])],
        "personal_urls": grav.get("urls", []),
        "avatar": grav.get("photo") or (got.get("gravatar_avatar", {}) or {}).get("url", ""),
    }
    # A name declared in git commit metadata is self-reported and valuable.
    for ca in (got.get("github", {}) or {}).get("commit_authors", []):
        if ca.get("commit_name") and ca["commit_name"] not in identity["names"]:
            identity["names"].append(ca["commit_name"])

    breach_sources = {k: got[k] for k in
                      ("xposedornot", "hudsonrock", "leakcheck", "hibp", "breachdirectory")
                      if k in got}
    all_breaches = sorted(
        set((got.get("xposedornot", {}) or {}).get("breaches", []))
        | {b["name"] for b in (got.get("hibp", {}) or {}).get("breaches", [])}
        | set((got.get("leakcheck", {}) or {}).get("sources", []))
        | set((got.get("breachdirectory", {}) or {}).get("sources", [])))

    steps = []
    if identity["names"]:
        steps.append(f"Real name candidates: {', '.join(identity['names'])} — feed the "
                     "best one to osint.variants to generate handles, then sweep them.")
    if identity["linked_accounts"]:
        steps.append("Linked accounts came from the owner's own profile — treat them "
                     "as confirmed and run osint.profile on each.")
    if classification["plus_tag"]:
        steps.append(f"Plus-tag '{classification['plus_tag']}' shows where they used "
                     f"this address; the base address is {classification['base_local']}@{domain}.")
    if classification["disposable"]:
        steps.append("Disposable domain — this address was made to be thrown away; "
                     "expect a thin footprint.")
    if classification["role_account"]:
        steps.append("Role account (not a person) — pivot to the organization instead "
                     "(osint.records, osint.websearch with site: the domain).")
    if all_breaches:
        steps.append(f"In {len(all_breaches)} breach corpora — the breach NAMES tell you "
                     "which services they used; each is a platform to check for a profile.")
    if (got.get("hudsonrock", {}) or {}).get("infected"):
        steps.append("Hudson Rock reports infostealer infection — treat any credential "
                     "of theirs as compromised; relevant if this is your own address.")
    if not identity["names"] and not all_breaches:
        steps.append("Thin result. Try the local part as a username (osint.username) "
                     "and search the address in quotes (osint.websearch).")

    return {"address": addr, "local": local, "domain": domain,
            "hashes": hashes(addr), "classification": classification,
            "identity": identity, "breaches": {"names": all_breaches,
                                               "by_source": breach_sources},
            "dns": got.get("mx", {}), "search": got.get("websearch", {}),
            "raw_sources": got, "sources_up": sorted(got), "sources_down": down,
            "next_steps": steps}


def _compact_lines(res: dict) -> list[str]:
    c = res["classification"]
    empty, failed = fetch.split_down(res["sources_down"])
    lines = [f"# email: {res['address']}",
             f"# sources with data: {', '.join(res['sources_up']) or 'none'}"]
    if empty:
        lines.append(f"# nothing found by: {', '.join(empty)}")
    if failed:
        lines.append(f"# unavailable (no key / error): {', '.join(failed)}")

    flags = [k for k in ("role_account", "disposable") if c[k]]
    lines.append(f"## CLASSIFICATION  {', '.join(flags) if flags else 'personal-looking'}"
                 + (f"  plus-tag={c['plus_tag']}" if c["plus_tag"] else ""))
    if res["dns"].get("mx"):
        lines.append(f"  mx: {', '.join(res['dns']['mx'][:5])}")
    elif res["dns"]:
        lines.append(f"  mx: none ({res['dns'].get('rcode', '?')}) — domain can't receive mail")

    idt = res["identity"]
    lines.append("## IDENTITY")
    if idt["names"]:
        lines.append(f"  names        {', '.join(idt['names'])}")
    if idt["usernames"]:
        lines.append(f"  usernames    {', '.join(idt['usernames'])}")
    if idt["location"]:
        lines.append(f"  location     {idt['location']}")
    if idt["bio"]:
        lines.append(f"  bio          {idt['bio'][:200]}")
    if not any((idt["names"], idt["usernames"], idt["location"], idt["bio"])):
        lines.append("  (nothing found)")
    for a in idt["linked_accounts"]:
        mark = "verified" if a.get("verified") else "claimed"
        lines.append(f"  account      {a.get('platform', ''):<14} {a.get('url', '')} [{mark}]")
    for u in idt["personal_urls"]:
        lines.append(f"  url          {u.get('title', '')} {u.get('url', '')}")

    b = res["breaches"]
    lines.append(f"## BREACH EXPOSURE ({len(b['names'])} corpora)")
    if b["names"]:
        lines.append("  " + ", ".join(b["names"]))
    else:
        lines.append("  none reported by the sources that answered")
    hr = res["raw_sources"].get("hudsonrock", {})
    if hr.get("infected"):
        lines.append(f"  INFOSTEALER: {hr.get('stealer_count', 0)} infected machine(s)")
        for c2 in hr.get("computers", []):
            lines.append(f"    {c2.get('date', '')} {c2.get('os', '')} "
                         f"{c2.get('malware', '')} {c2.get('ip', '')}")

    s = res.get("search") or {}
    if s.get("results"):
        lines.append(f"## WEB MENTIONS ({len(s['results'])})")
        for r in s["results"][:15]:
            lines.append(f"  [{r['agreement']}x] {r['url']}")
            if r["title"]:
                lines.append(f"        {r['title'][:110]}")
    lines.append(f"## HASHES  md5={res['hashes']['md5']}  sha256={res['hashes']['sha256'][:32]}...")
    lines.append("## NEXT")
    lines += [f"  - {x}" for x in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.email",
        description="Identity, breach exposure and web presence for an email address.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m osint.email someone@example.com\n"
                "  python -m osint.email someone@example.com --json\n"
                "  python -m osint.email someone@example.com --skip breaches,search\n"
                "\noptional keys: HIBP_API_KEY, GITHUB_TOKEN, RAPIDAPI_KEY\n"),
    )
    p.add_argument("address", nargs="?", help="Email address to investigate.")
    p.add_argument("--timeout", type=float, default=20.0, help="Per-source timeout (default 20).")
    p.add_argument("--skip", default="",
                   help="Comma-separated groups to skip: identity,breaches,search,dns")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.address:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(args.address, timeout=args.timeout,
                  skip=tuple(s.strip() for s in args.skip.split(",") if s.strip()))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
