"""Full person investigation: run every osint tool, then correlate the results.

The orchestrator. Give it whatever you have — a name, a handle, an email, an
employer — and it runs the whole package in dependency order, feeding each
stage's output into the next, then scores every account it found by how strongly
the evidence ties it to your target.

Stages (each independently runnable with ``--stages``, so you can re-run one
with different parameters instead of repeating the whole sweep):

    seed      expand the name into handle and email candidates (osint.variants)
    username  sweep the handle candidates across ~70 platforms (osint.username)
    email     enrich every known/derived address (osint.email)
    search    multi-engine dorks incl. every major social platform (osint.websearch)
    linkedin  find and parse the public LinkedIn profile (osint.linkedin)
    records   Wikidata / SEC / registries / sanctions (osint.records)
    profile   extract identity data from every URL found above (osint.profile)
    correlate score and merge everything into one identity picture

EVERY STAGE'S RAW OUTPUT IS RETURNED, not just the final answer. That is
deliberate: the operator — human or model — is better than any heuristic at
spotting that a hit is the wrong "John Smith", that a handle needs a suffix
dropped, or that a bio names a city worth searching. Read the stage output,
change one input, re-run one stage.

Confidence is evidence-based and always explained:

    CONFIRMED  the target's own profile links to it (rel=me, a verified Gravatar
               account, or a handle declared on Wikidata). Self-declaration is
               the only real proof available in OSINT.
    HIGH       several independent signals agree (name + location + handle)
    MEDIUM     one solid signal (exact handle match on a platform that
               discriminates, name match in a profile)
    LOW        the handle exists but nothing ties it to your target — a
               different person may simply have the same username

Nothing is asserted as fact. Same-handle-different-person is the default failure
mode of username OSINT, and the scoring is built to keep that visible rather than
paper over it.

Safety: read-only throughout. Every underlying tool is passive — public pages,
public APIs, DNS. No logins, no writes, no contact with the subject.

Legal note: this aggregates public information about a person. That is lawful in
most jurisdictions and is what a background check, a due-diligence report or a
red-team recon phase already does — but aggregation is exactly what data
protection law (GDPR, KVKK, CCPA) regulates. Have a legitimate basis before you
run it on someone who isn't you or your client. See the folder README.

Usage:
    python -m osint.person --name "Ada Lovelace"
    python -m osint.person --handle torvalds --json
    python -m osint.person --name "Ada Lovelace" --email ada@example.com \
        --employer "Analytical Engines" --location London
    python -m osint.person --handle torvalds --stages username,profile,correlate
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse as up

from common.output import emit, log
from osint import fetch

STAGES = ("seed", "username", "email", "search", "linkedin", "records",
          "profile", "correlate")


def _norm_name(text: str) -> str:
    return re.sub(r"[^a-z]", "", (text or "").lower())


def _name_tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z]+", (text or "").lower()) if len(t) > 2}


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
        if _norm_name(profile_name) == _norm_name(target_name):
            score += 30
            why.append(f"profile name '{profile_name}' matches the target name exactly")
        else:
            shared = _name_tokens(profile_name) & _name_tokens(target_name)
            if shared:
                score += 15
                why.append(f"profile name shares {', '.join(sorted(shared))} with the target")
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


def run(
    *,
    name: str = "",
    handles: list[str] | None = None,
    emails: list[str] | None = None,
    email_domain: str = "",
    location: str = "",
    employer: str = "",
    stages: tuple[str, ...] = STAGES,
    max_handles: int = 8,
    max_profiles: int = 12,
    max_queries: int = 10,
    timeout: float = 20.0,
) -> dict:
    """Run the full investigation and correlate everything found.

    Args:
        name: The target's full name, if known.
        handles: Known handles. Combined with any derived from ``name``.
        emails: Known addresses. Combined with any derived from ``name`` +
            ``email_domain``.
        email_domain: Employer/personal mail domain for address permutation.
        location: City/country, used to disambiguate and to score.
        employer: Company, used to disambiguate and to score.
        stages: Which stages to run, in ``STAGES`` order.
        max_handles: How many derived handle candidates to actually sweep.
            Kept small on purpose — the top few are the realistic ones.
        max_profiles: Cap on URLs fetched in the profile stage.
        max_queries: Cap on search-engine dork queries.
        timeout: Per-request timeout passed to the underlying tools.

    Returns:
        ``{"target","stages_run","seed","username","email","search","linkedin",
        "records","profiles","accounts","identity","next_steps"}`` — every stage
        raw, plus the correlated view.

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
                            "employer": employer},
                 "stages_run": [], "seed": {}, "username": {}, "email": {},
                 "search": {}, "linkedin": {}, "records": {}, "profiles": [],
                 "accounts": [], "identity": {}, "next_steps": []}

    # --- seed: expand the name into candidates ------------------------------
    sweep_handles = list(known_handles)
    if "seed" in stages and name:
        from osint import variants
        log("[*] stage seed: expanding name into candidates ...")
        seed = variants.run(name=name, email_domain=email_domain)
        out["seed"] = seed
        out["stages_run"].append("seed")
        for h in seed["handles"]:
            if h not in sweep_handles and len(sweep_handles) < max_handles + len(known_handles):
                sweep_handles.append(h)
        known_emails += [e for e in seed.get("emails", []) if e not in known_emails]

    # --- username: sweep the platform table ---------------------------------
    if "username" in stages and sweep_handles:
        from osint import username as username_mod
        log(f"[*] stage username: sweeping {len(sweep_handles)} handle(s) ...")
        try:
            out["username"] = username_mod.run(sweep_handles, timeout=timeout)
            out["stages_run"].append("username")
        except ValueError as exc:
            out["username"] = {"error": str(exc)}

    # --- email: enrich every address ----------------------------------------
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

    # --- search: multi-engine dorks -----------------------------------------
    if "search" in stages and (name or sweep_handles):
        from osint import websearch
        log("[*] stage search: multi-engine dorks ...")
        out["search"] = websearch.run(
            person=name, handle=sweep_handles[0] if sweep_handles else "",
            extra=" ".join(f'"{x}"' for x in (employer, location) if x),
            max_queries=max_queries, timeout=45.0)
        out["stages_run"].append("search")

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

    # --- gather every URL worth extracting ----------------------------------
    candidate_urls: list[str] = []

    def add_url(u: str) -> None:
        u = (u or "").strip()
        if u.startswith("http") and u.rstrip("/") not in [
                c.rstrip("/") for c in candidate_urls]:
            candidate_urls.append(u)

    for hit in (out.get("username") or {}).get("found", []):
        add_url(hit["url"])
    for lst in ((out.get("search") or {}).get("by_platform") or {}).values():
        for hit in lst[:2]:
            add_url(hit["url"])
    for p in (out.get("linkedin") or {}).get("profiles", [])[:2]:
        add_url(p["url"])
    for addr, data in (out.get("email") or {}).items():
        for acct in (data.get("identity", {}) or {}).get("linked_accounts", []):
            add_url(acct.get("url", ""))
        for u in (data.get("identity", {}) or {}).get("personal_urls", []):
            add_url(u.get("url", ""))
    for site in (out.get("records") or {}).get("person", {}).get("website", []) or []:
        add_url(site)

    # --- profile: extract identity data from each URL -----------------------
    declared_urls: set[str] = set()
    if "profile" in stages and candidate_urls:
        from osint import profile as profile_mod
        targets = candidate_urls[:max_profiles]
        log(f"[*] stage profile: extracting from {len(targets)} URL(s) ...")
        sources = {u: (lambda url=u: profile_mod.run(url, timeout=timeout))
                   for u in targets}
        got, down = fetch.gather(sources, workers=6, timeout=timeout * 6)
        for url, data in got.items():
            out["profiles"].append({
                "url": url,
                "identity": data.get("identity", {}),
                "rel_me": data.get("rel_me", []),
                "links": data.get("links", []),
                "emails": data.get("emails", []),
                "birth_hints": data.get("birth_hints", []),
                "blocked": data.get("blocked", False),
            })
            for l in data.get("rel_me", []):
                declared_urls.add(l["url"].rstrip("/"))
        out["profile_failures"] = down
        out["stages_run"].append("profile")

    # --- correlate ----------------------------------------------------------
    if "correlate" in stages:
        log("[*] stage correlate: scoring accounts ...")
        # Everything the target themselves declared, from any source.
        for addr, data in (out.get("email") or {}).items():
            for acct in (data.get("identity", {}) or {}).get("linked_accounts", []):
                if acct.get("verified"):
                    declared_urls.add((acct.get("url") or "").rstrip("/"))
        wd_handles = (out.get("records") or {}).get("person", {}).get("handles", {}) or {}

        # Bios/names discovered per URL, so scoring can use them.
        by_url: dict[str, dict] = {}
        for p in out["profiles"]:
            ident = p["identity"] or {}
            by_url[p["url"].rstrip("/")] = {
                "profile_name": ident.get("name", ""),
                "bio": " ".join(str(v) for v in (
                    ident.get("headline", ""), ident.get("locality", ""))),
            }

        all_handles = {h.lower() for h in sweep_handles}
        all_emails = {e.lower() for e in known_emails}

        accounts: list[dict] = []
        seen_urls: set[str] = set()

        def push(url: str, platform: str, handle: str, **extra) -> None:
            key = (url or "").rstrip("/")
            if not key or key in seen_urls:
                return
            seen_urls.add(key)
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
            for l in p["links"]:
                push(l["url"], l["platform"], l["handle"],
                     source=f"link on {p['url']}")
        for platform, val in wd_handles.items():
            for v in (val if isinstance(val, list) else [val]):
                base = {"x_twitter": "https://x.com/", "instagram": "https://instagram.com/",
                        "facebook": "https://facebook.com/", "github": "https://github.com/",
                        "linkedin": "https://www.linkedin.com/in/"}.get(platform, "")
                if base:
                    push(f"{base}{v}", platform, str(v), source="wikidata",
                         self_declared=True, declared_by="declared on Wikidata")
        for platform, hits in ((out.get("search") or {}).get("by_platform") or {}).items():
            for h in hits[:3]:
                push(h["url"], platform, "", source="websearch",
                     agreement=h.get("agreement", 1))

        rank = {"CONFIRMED": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        accounts.sort(key=lambda a: (rank[a["confidence"]], -a["score"], a["platform"]))
        out["accounts"] = accounts

        # Merge every name/location/employer claim we saw, with provenance.
        def collect(field: str) -> list[dict]:
            vals: list[dict] = []

            def add(v: str, src: str) -> None:
                v = (v or "").strip()
                if v and not any(x["value"].lower() == v.lower() for x in vals):
                    vals.append({"value": v, "sources": [src]})
                elif v:
                    for x in vals:
                        if x["value"].lower() == v.lower() and src not in x["sources"]:
                            x["sources"].append(src)
            for p in out["profiles"]:
                add((p["identity"] or {}).get(field, ""), p["url"])
            for addr, data in (out.get("email") or {}).items():
                idt = data.get("identity", {}) or {}
                if field == "name":
                    for n in idt.get("names", []):
                        add(n, f"gravatar/{addr}")
                elif field == "locality":
                    add(idt.get("location", ""), f"gravatar/{addr}")
            li = (out.get("linkedin") or {}).get("parsed", {}).get("identity", {})
            add(li.get("name" if field == "name" else field, ""), "linkedin")
            rec = (out.get("records") or {}).get("person", {})
            if field == "name":
                add(rec.get("name", ""), "wikidata")
            return sorted(vals, key=lambda x: -len(x["sources"]))

        li_parsed = (out.get("linkedin") or {}).get("parsed", {})
        rec_person = (out.get("records") or {}).get("person", {})
        out["identity"] = {
            "names": collect("name"),
            "locations": collect("locality"),
            "headlines": collect("headline"),
            "birth_date": (rec_person.get("birth_date") or []),
            "birth_hints": sorted({b for p in out["profiles"] for b in p["birth_hints"]}),
            "employers": ([e["name"] for e in li_parsed.get("experience", [])]
                          + (rec_person.get("employer") or [])),
            "education": ([e["name"] for e in li_parsed.get("education", [])]
                          + (rec_person.get("educated_at") or [])),
            "emails": sorted({e for p in out["profiles"] for e in p["emails"]}
                             | set(known_emails)),
            "confirmed_accounts": [a["url"] for a in accounts
                                   if a["confidence"] == "CONFIRMED"],
        }
        out["stages_run"].append("correlate")

    # --- what to do next ----------------------------------------------------
    steps: list[str] = []
    names = [n["value"] for n in out["identity"].get("names", [])]
    if names and names[0] and _norm_name(names[0]) != _norm_name(name):
        steps.append(f"A different name spelling dominates the evidence: "
                     f"'{names[0]}'. Re-run with --name \"{names[0]}\".")
    low = [a for a in out["accounts"] if a["confidence"] == "LOW"]
    if low:
        steps.append(f"{len(low)} LOW-confidence accounts are handle matches with "
                     "nothing else behind them — open a couple before believing any.")
    if out["identity"].get("emails"):
        steps.append("Run the email stage on any newly discovered address: "
                     f"--email {out['identity']['emails'][0]}")
    if not out["accounts"]:
        steps.append("Nothing found. Check the name spelling, try the handle you "
                     "already know (--handle), and remember most private people "
                     "have a genuinely small public footprint.")
    steps.append("Re-run a single stage with different inputs instead of the whole "
                 "sweep, e.g. --stages username --handle <corrected-handle>.")
    out["next_steps"] = steps
    return out


def _compact_lines(res: dict) -> list[str]:
    t = res["target"]
    lines = [f"# person: {t['name'] or ', '.join(t['handles']) or ', '.join(t['emails'])}",
             f"# stages run: {', '.join(res['stages_run']) or 'none'}"]

    idt = res.get("identity") or {}
    if idt:
        lines.append("## IDENTITY (merged, with provenance)")
        for n in idt.get("names", [])[:5]:
            lines.append(f"  name       {n['value']}   [{len(n['sources'])} source(s): "
                         f"{', '.join(s.split('//')[-1][:40] for s in n['sources'][:3])}]")
        for l in idt.get("locations", [])[:3]:
            lines.append(f"  location   {l['value']}   [{len(l['sources'])} source(s)]")
        for h in idt.get("headlines", [])[:3]:
            lines.append(f"  headline   {h['value'][:120]}")
        if idt.get("birth_date"):
            lines.append(f"  born       {', '.join(str(b) for b in idt['birth_date'])}")
        if idt.get("birth_hints"):
            lines.append(f"  dob hints  {', '.join(idt['birth_hints'][:5])}  (unverified)")
        if idt.get("employers"):
            lines.append(f"  employers  {', '.join(dict.fromkeys(idt['employers']))}")
        if idt.get("education"):
            lines.append(f"  education  {', '.join(dict.fromkeys(idt['education']))}")
        if idt.get("emails"):
            lines.append(f"  emails     {', '.join(idt['emails'][:8])}")

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

    u = res.get("username") or {}
    if u.get("found") is not None:
        lines.append(f"## STAGE username: {len(u.get('found', []))} hits across "
                     f"{u.get('checked_sites', 0)} sites for "
                     f"{', '.join(u.get('usernames', []))}")
        if u.get("unreliable_sites"):
            lines.append(f"  unreliable sites ignored: {', '.join(u['unreliable_sites'])}")
    s = res.get("search") or {}
    if s:
        lines.append(f"## STAGE search: {s.get('total_unique', 0)} URLs from "
                     f"{len(s.get('engines_used', []))} engines "
                     f"({len(s.get('queries', []))} queries)")
    li = res.get("linkedin") or {}
    if li.get("profiles"):
        lines.append(f"## STAGE linkedin: {len(li['profiles'])} candidate profile(s)")
        for p in li["profiles"][:3]:
            lines.append(f"  {p['url']}  {p['title'][:80]}")
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
                '  python -m osint.person --handle torvalds --json\n'
                '  python -m osint.person --name "Ada Lovelace" --email ada@example.com \\\n'
                '      --employer "Analytical Engines" --location London\n'
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
    p.add_argument("--stages", default="",
                   help=f"Comma-separated subset of: {', '.join(STAGES)}")
    p.add_argument("--max-handles", type=int, default=8,
                   help="Derived handle candidates to sweep (default 8).")
    p.add_argument("--max-profiles", type=int, default=12,
                   help="URLs to fetch in the profile stage (default 12).")
    p.add_argument("--max-queries", type=int, default=10,
                   help="Search dork queries (default 10).")
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
                  employer=args.employer, stages=stages,
                  max_handles=args.max_handles, max_profiles=args.max_profiles,
                  max_queries=args.max_queries, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
