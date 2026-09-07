"""Search public records for a person or company: registries, filings, sanctions.

The structured-data half of person OSINT. Where :mod:`osint.websearch` finds
mentions, this queries authoritative registers that publish machine-readable
facts — dates of birth, education, employers, directorships, corporate
addresses, regulatory filings and sanctions listings.

Sources, queried in parallel, each independently optional:

    Wikidata          free, no auth. Structured claims for notable people: date
                      of birth, birthplace, citizenship, education, employers,
                      occupations, and the person's own declared social handles.
                      The best free source of a verified DoB that exists.
    Wikipedia         free, no auth. Summary paragraph for context.
    SEC EDGAR         free, no auth (a contact User-Agent is required by the
                      SEC). Full-text search over US securities filings — finds
                      officers, directors, beneficial owners, and the companies
                      they file for.
    GLEIF             free, no auth. Legal Entity Identifier register: legal
                      name, registered and HQ address, parent company, status.
    OpenCorporates    $OPENCORPORATES_API_KEY. Company officers across ~140
                      jurisdictions.
    Companies House   $COMPANIES_HOUSE_KEY. UK companies and their officers,
                      including partial dates of birth for directors.
    OpenSanctions     $OPENSANCTIONS_API_KEY. Consolidated sanctions, PEP and
                      watchlist screening.

Keyed sources are skipped silently when their env var is absent, so the tool
degrades from seven sources to four rather than failing.

Scope note: this searches registers that are published for public inspection.
It does not touch paid people-search brokers, credit files, voter rolls, or
anything requiring a subscription to personal data — see the folder README for
where that line is and why.

Safety: read-only. Queries public APIs; writes nothing anywhere.

Usage:
    python -m osint.records "Ada Lovelace"
    python -m osint.records "Elon Musk" --json
    python -m osint.records "Acme Corporation" --kind company
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse as up

from common.output import emit, log
from osint import fetch

# The SEC requires a User-Agent identifying the requester; anonymous scraping is
# explicitly blocked. Override with $SEC_CONTACT to use your own address.
_SEC_UA = os.environ.get(
    "SEC_CONTACT", "cybersecurity-tools OSINT research (contact via repository)")

# Wikidata property ids -> our field names. Values are entity refs or literals.
_WD_PROPS = {
    "P569": "birth_date", "P570": "death_date", "P19": "birth_place",
    "P27": "citizenship", "P106": "occupation", "P108": "employer",
    "P69": "educated_at", "P39": "position_held", "P937": "work_location",
    "P856": "website", "P2002": "x_twitter", "P2003": "instagram",
    "P2013": "facebook", "P2037": "github", "P4033": "mastodon",
    "P6634": "linkedin", "P2035": "linkedin_alt", "P1153": "scopus",
    "P496": "orcid", "P734": "family_name", "P735": "given_name",
}


def _wd_value(claim: dict) -> tuple[str, str]:
    """Return ``(display_value, entity_id_or_empty)`` for one Wikidata claim."""
    snak = (claim.get("mainsnak") or {}).get("datavalue") or {}
    val = snak.get("value")
    if isinstance(val, dict):
        if "id" in val:                      # entity reference, resolve later
            return "", val["id"]
        if "time" in val:                    # +1815-12-10T00:00:00Z
            return str(val["time"]).lstrip("+").split("T")[0], ""
        if "text" in val:
            return str(val["text"]), ""
    return (str(val) if val is not None else ""), ""


def _wikidata(query: str, kind: str, timeout: float) -> dict:
    """Search Wikidata and expand the best matching entity's claims."""
    data, _ = fetch.get_json(
        "https://www.wikidata.org/w/api.php?action=wbsearchentities&"
        f"search={up.quote(query)}&language=en&format=json&limit=5", timeout=timeout)
    hits = (data or {}).get("search") or []
    if not hits:
        return {}

    candidates = [{"id": h["id"], "label": h.get("label", ""),
                   "description": h.get("description", ""),
                   "url": f"https://www.wikidata.org/wiki/{h['id']}"} for h in hits]

    qid = hits[0]["id"]
    ent, _ = fetch.get_json(
        f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json", timeout=timeout)
    entity = ((ent or {}).get("entities") or {}).get(qid) or {}
    claims = entity.get("claims") or {}

    fields: dict[str, list[str]] = {}
    to_resolve: dict[str, list[str]] = {}
    for prop, field in _WD_PROPS.items():
        for claim in claims.get(prop, []):
            text, ref = _wd_value(claim)
            if text:
                fields.setdefault(field, []).append(text)
            elif ref:
                to_resolve.setdefault(field, []).append(ref)

    # Resolve referenced entities (employer, school, city) to labels in one call.
    ids = sorted({i for refs in to_resolve.values() for i in refs})
    labels: dict[str, str] = {}
    for chunk in [ids[i:i + 45] for i in range(0, len(ids), 45)]:
        lab, _ = fetch.get_json(
            "https://www.wikidata.org/w/api.php?action=wbgetentities&ids="
            f"{'|'.join(chunk)}&props=labels&languages=en&format=json", timeout=timeout)
        for eid, body in ((lab or {}).get("entities") or {}).items():
            labels[eid] = ((body.get("labels") or {}).get("en") or {}).get("value", eid)
    for field, refs in to_resolve.items():
        fields.setdefault(field, []).extend(labels.get(r, r) for r in refs)

    is_human = any(_wd_value(c)[1] == "Q5" for c in claims.get("P31", []))
    return {"qid": qid, "url": f"https://www.wikidata.org/wiki/{qid}",
            "label": (entity.get("labels", {}).get("en") or {}).get("value", ""),
            "description": (entity.get("descriptions", {}).get("en") or {}).get("value", ""),
            "is_human": is_human, "fields": fields, "candidates": candidates}


def _wikipedia(query: str, timeout: float) -> dict:
    """English Wikipedia summary (REST API, free, no auth)."""
    data, _ = fetch.get_json(
        "https://en.wikipedia.org/api/rest_v1/page/summary/"
        f"{up.quote(query.replace(' ', '_'))}", timeout=timeout)
    if not isinstance(data, dict) or data.get("type", "").endswith("not_found"):
        return {}
    return {"title": data.get("title", ""), "extract": data.get("extract", ""),
            "url": (data.get("content_urls", {}).get("desktop", {}) or {}).get("page", ""),
            "description": data.get("description", "")}


def _sec_edgar(query: str, timeout: float) -> dict:
    """SEC EDGAR full-text search over US securities filings."""
    data, _ = fetch.get_json(
        f'https://efts.sec.gov/LATEST/search-index?q=%22{up.quote(query)}%22',
        headers={"User-Agent": _SEC_UA}, timeout=timeout)
    hits = ((data or {}).get("hits") or {}).get("hits") or []
    if not hits:
        return {}
    out = []
    for h in hits[:20]:
        src = h.get("_source", {})
        adsh = str(h.get("_id", "")).split(":")[0]
        cik = (src.get("ciks") or [""])[0]
        out.append({
            "names": src.get("display_names", []),
            "form": src.get("file_type", src.get("root_form", "")),
            "date": src.get("file_date", ""),
            "cik": cik,
            "url": (f"https://www.sec.gov/Archives/edgar/data/{cik.lstrip('0')}/"
                    f"{adsh.replace('-', '')}/{adsh}-index.htm" if cik and adsh else ""),
        })
    total = ((data.get("hits") or {}).get("total") or {}).get("value", len(out))
    return {"total": total, "filings": out}


def _gleif(query: str, timeout: float) -> dict:
    """GLEIF Legal Entity Identifier register (free, no auth)."""
    data, _ = fetch.get_json(
        "https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]="
        f"{up.quote(query)}&page[size]=10",
        headers={"Accept": "application/vnd.api+json"}, timeout=timeout)
    recs = (data or {}).get("data") or []
    out = []
    for r in recs:
        ent = ((r.get("attributes") or {}).get("entity") or {})
        legal = ent.get("legalAddress") or {}
        out.append({
            "lei": r.get("id", ""),
            "name": (ent.get("legalName") or {}).get("name", ""),
            "status": ent.get("status", ""),
            "jurisdiction": ent.get("jurisdiction", ""),
            "address": ", ".join(filter(None, [
                " ".join(legal.get("addressLines") or []), legal.get("city", ""),
                legal.get("region", ""), legal.get("postalCode", ""),
                legal.get("country", "")])),
            "url": f"https://search.gleif.org/#/record/{r.get('id', '')}",
        })
    return {"entities": out} if out else {}


def _opencorporates(query: str, timeout: float) -> dict:
    """OpenCorporates officer search ($OPENCORPORATES_API_KEY)."""
    key = os.environ.get("OPENCORPORATES_API_KEY", "")
    if not key:
        return {}
    data, _ = fetch.get_json(
        f"https://api.opencorporates.com/v0.4/officers/search?q={up.quote(query)}"
        f"&api_token={key}", timeout=timeout)
    officers = ((data or {}).get("results") or {}).get("officers") or []
    return {"officers": [{
        "name": (o.get("officer") or {}).get("name", ""),
        "position": (o.get("officer") or {}).get("position", ""),
        "company": ((o.get("officer") or {}).get("company") or {}).get("name", ""),
        "jurisdiction": (o.get("officer") or {}).get("jurisdiction_code", ""),
        "url": (o.get("officer") or {}).get("opencorporates_url", ""),
    } for o in officers[:25]]} if officers else {}


def _companies_house(query: str, timeout: float) -> dict:
    """UK Companies House officer search ($COMPANIES_HOUSE_KEY)."""
    import base64
    key = os.environ.get("COMPANIES_HOUSE_KEY", "")
    if not key:
        return {}
    auth = base64.b64encode(f"{key}:".encode()).decode()
    data, _ = fetch.get_json(
        f"https://api.company-information.service.gov.uk/search/officers?q={up.quote(query)}",
        headers={"Authorization": f"Basic {auth}"}, timeout=timeout)
    items = (data or {}).get("items") or []
    return {"officers": [{
        "name": i.get("title", ""),
        "dob": (f"{(i.get('date_of_birth') or {}).get('month', '')}/"
                f"{(i.get('date_of_birth') or {}).get('year', '')}"
                if i.get("date_of_birth") else ""),
        "address": (i.get("address_snippet") or ""),
        "appointments": i.get("appointment_count", 0),
        "url": "https://find-and-update.company-information.service.gov.uk"
               + i.get("links", {}).get("self", ""),
    } for i in items[:25]]} if items else {}


def _opensanctions(query: str, timeout: float) -> dict:
    """OpenSanctions screening ($OPENSANCTIONS_API_KEY)."""
    key = os.environ.get("OPENSANCTIONS_API_KEY", "")
    if not key:
        return {}
    data, _ = fetch.get_json(
        f"https://api.opensanctions.org/search/default?q={up.quote(query)}&limit=10",
        headers={"Authorization": f"ApiKey {key}"}, timeout=timeout)
    results = (data or {}).get("results") or []
    return {"matches": [{
        "name": r.get("caption", ""), "schema": r.get("schema", ""),
        "datasets": r.get("datasets", []), "score": r.get("score", 0),
        "url": f"https://www.opensanctions.org/entities/{r.get('id', '')}/",
    } for r in results]} if results else {}


def run(
    query: str,
    *,
    kind: str = "auto",
    timeout: float = 25.0,
) -> dict:
    """Search every configured public register for ``query``.

    Args:
        query: A person's full name, or a company name.
        kind: ``person``, ``company``, or ``auto`` (queries both sets).
        timeout: Per-source timeout in seconds.

    Returns:
        ``{"query","kind","person","company","sources_up","sources_down",
        "next_steps"}``.

    Raises:
        ValueError: If ``query`` is empty or ``kind`` is unknown.
    """
    q = query.strip()
    if not q:
        raise ValueError("give a name to search for")
    if kind not in ("auto", "person", "company"):
        raise ValueError(f"kind must be person/company/auto, got {kind!r}")

    sources: dict[str, object] = {"wikidata": lambda: _wikidata(q, kind, timeout)}
    if kind in ("auto", "person"):
        sources["wikipedia"] = lambda: _wikipedia(q, timeout)
        sources["companies_house"] = lambda: _companies_house(q, timeout)
        sources["opencorporates"] = lambda: _opencorporates(q, timeout)
        sources["opensanctions"] = lambda: _opensanctions(q, timeout)
    if kind in ("auto", "company"):
        sources["gleif"] = lambda: _gleif(q, timeout)
    sources["sec_edgar"] = lambda: _sec_edgar(q, timeout)

    log(f"[*] querying {len(sources)} registers for {q!r} ...")
    got, down = fetch.gather(sources, workers=7, timeout=timeout * 3)  # type: ignore[arg-type]

    wd = got.get("wikidata", {}) or {}
    f = wd.get("fields", {}) or {}
    person = {
        "name": wd.get("label", ""),
        "description": wd.get("description", ""),
        "is_human": wd.get("is_human", False),
        "birth_date": f.get("birth_date", []),
        "death_date": f.get("death_date", []),
        "birth_place": f.get("birth_place", []),
        "citizenship": f.get("citizenship", []),
        "occupation": f.get("occupation", []),
        "employer": f.get("employer", []),
        "educated_at": f.get("educated_at", []),
        "position_held": f.get("position_held", []),
        "website": f.get("website", []),
        "handles": {k: v for k, v in f.items()
                    if k in ("x_twitter", "instagram", "facebook", "github",
                             "mastodon", "linkedin", "linkedin_alt", "orcid")},
        "wikidata_url": wd.get("url", ""),
        "wikipedia": got.get("wikipedia", {}),
        "officer_records": ((got.get("companies_house", {}) or {}).get("officers", [])
                            + (got.get("opencorporates", {}) or {}).get("officers", [])),
        "sanctions": (got.get("opensanctions", {}) or {}).get("matches", []),
    }
    company = {"gleif": (got.get("gleif", {}) or {}).get("entities", []),
               "sec_filings": (got.get("sec_edgar", {}) or {}).get("filings", []),
               "sec_total": (got.get("sec_edgar", {}) or {}).get("total", 0)}

    steps = []
    if person["birth_date"]:
        steps.append(f"Date of birth {person['birth_date'][0]} comes from Wikidata — "
                     "verify against a second source before relying on it.")
    if person["handles"]:
        steps.append("Wikidata lists self-declared handles: "
                     + ", ".join(f"{k}={v[0]}" for k, v in person["handles"].items() if v)
                     + ". Run osint.username / osint.profile on them.")
    if person["educated_at"] or person["employer"]:
        steps.append("Education and employers are strong search disambiguators — "
                     "pass them to osint.websearch --extra.")
    if person["officer_records"]:
        steps.append("Company officer records give a registered address and often a "
                     "partial DoB. Cross-check the address against other findings.")
    if company["sec_filings"]:
        steps.append(f"{company['sec_total']} SEC filings mention this name; the filing "
                     "pages list officers, addresses and signatures.")
    if wd.get("candidates") and len(wd["candidates"]) > 1:
        steps.append("Several Wikidata entities matched — check `candidates` and "
                     "re-run with a more specific name if the top one is wrong.")
    if not got:
        steps.append("No register answered. For a non-notable private individual "
                     "this is the normal result: they simply aren't in these "
                     "datasets. Use osint.websearch and osint.username instead.")

    return {"query": q, "kind": kind, "person": person, "company": company,
            "wikidata_candidates": wd.get("candidates", []),
            "raw_sources": got, "sources_up": sorted(got), "sources_down": down,
            "next_steps": steps}


def _compact_lines(res: dict) -> list[str]:
    p, c = res["person"], res["company"]
    empty, failed = fetch.split_down(res["sources_down"])
    lines = [f"# records: {res['query']}  [{res['kind']}]",
             f"# sources with data: {', '.join(res['sources_up']) or 'none'}"]
    if empty:
        lines.append(f"# no match in: {', '.join(empty)}")
    if failed:
        lines.append(f"# unavailable: {', '.join(failed)}")

    if p["name"]:
        lines.append(f"## WIKIDATA  {p['name']}  ({p['description']})")
        lines.append(f"  {p['wikidata_url']}")
        for field, label in (("birth_date", "born"), ("death_date", "died"),
                             ("birth_place", "birthplace"), ("citizenship", "citizen"),
                             ("occupation", "occupation"), ("employer", "employer"),
                             ("educated_at", "education"), ("position_held", "position"),
                             ("website", "website")):
            if p[field]:
                lines.append(f"  {label:<11} {', '.join(str(x) for x in p[field][:6])}")
        for k, v in p["handles"].items():
            if v:
                lines.append(f"  {k:<11} {', '.join(v)}")
    wiki = p.get("wikipedia") or {}
    if wiki.get("extract"):
        lines.append("## WIKIPEDIA")
        lines.append(f"  {wiki['extract'][:400]}")
        lines.append(f"  {wiki.get('url', '')}")
    if p["officer_records"]:
        lines.append(f"## COMPANY OFFICER RECORDS ({len(p['officer_records'])})")
        for o in p["officer_records"][:15]:
            bits = [o.get("name", ""), o.get("position", ""), o.get("company", ""),
                    o.get("dob", ""), o.get("address", "")]
            lines.append("  " + " | ".join(b for b in bits if b))
            if o.get("url"):
                lines.append(f"    {o['url']}")
    if p["sanctions"]:
        lines.append(f"## SANCTIONS / PEP MATCHES ({len(p['sanctions'])})")
        for s in p["sanctions"]:
            lines.append(f"  [{s['score']:.2f}] {s['name']} ({s['schema']}) "
                         f"{', '.join(s['datasets'][:3])}")
            lines.append(f"    {s['url']}")
    if c["gleif"]:
        lines.append(f"## GLEIF LEGAL ENTITIES ({len(c['gleif'])})")
        for e in c["gleif"]:
            lines.append(f"  {e['name']}  [{e['status']}] {e['jurisdiction']}  LEI={e['lei']}")
            if e["address"]:
                lines.append(f"    {e['address']}")
    if c["sec_filings"]:
        lines.append(f"## SEC EDGAR ({c['sec_total']} total, showing {len(c['sec_filings'])})")
        for fl in c["sec_filings"]:
            lines.append(f"  {fl['date']}  {fl['form']:<10} {', '.join(fl['names'][:2])}")
            if fl["url"]:
                lines.append(f"    {fl['url']}")
    if res["wikidata_candidates"] and len(res["wikidata_candidates"]) > 1:
        lines.append("## OTHER WIKIDATA MATCHES (in case the top one is the wrong person)")
        for cand in res["wikidata_candidates"][1:]:
            lines.append(f"  {cand['id']}  {cand['label']} — {cand['description']}")
    lines.append("## NEXT")
    lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.records",
        description="Search public registers: Wikidata, SEC EDGAR, GLEIF, registries, sanctions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.records "Ada Lovelace"\n'
                '  python -m osint.records "Elon Musk" --json\n'
                '  python -m osint.records "Acme Corporation" --kind company\n'
                '\noptional keys: OPENCORPORATES_API_KEY, COMPANIES_HOUSE_KEY,\n'
                '                OPENSANCTIONS_API_KEY, SEC_CONTACT\n'),
    )
    p.add_argument("query", nargs="?", help="Person or company name.")
    p.add_argument("--kind", default="auto", choices=("auto", "person", "company"),
                   help="Which register sets to query (default auto = both).")
    p.add_argument("--timeout", type=float, default=25.0, help="Per-source timeout.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.query:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(args.query, kind=args.kind, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
