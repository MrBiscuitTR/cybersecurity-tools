"""Expand known name parts into the handles and email addresses a person uses.

Deliberately narrow. This module does the part that is *deterministic* — given
"Cagan Efe Calidag", the set of handles that name can produce is a mechanical
enumeration, and it lands on ``cagancalidag``, ``caganefecalidag``, ``caganc``
and ``ccalidag`` without guessing anything.

What it does NOT do is guess name parts out of a run-together handle. An earlier
version scored every possible split of ``caganefecalidag`` and it was noise: the
correct reading is obvious to any human or LLM reading the string, and no
heuristic beats that. So the division of labour is:

    operator (you, or the LLM driving the MCP server)
        reads ``caganefecalidag``, sees "cagan efe calidag", and says so
    this module
        turns those parts into the full candidate set, exhaustively and fast

Every tool in this package therefore accepts a LIST of candidate handles, so the
operator can mix, match, edit and re-run: take the handles from here, drop the
ones that look wrong, add the two you know from memory, and sweep that set.

Safety: pure computation. No network, no I/O, no side effects.

Usage:
    python -m osint.variants --name "Cagan Efe Calidag"
    python -m osint.variants --name "Ada Lovelace" --email-domain example.com
    python -m osint.variants --handle xX_realdave1994_Xx     # normalize only
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata

from common.output import emit

# Handle decoration that is not identity. Stripping it turns "xX_dave_Xx",
# "realdave" and "dave1994" into "dave" — deterministic, unlike guessing splits.
AFFIX_PREFIXES = (
    "the", "real", "official", "im", "iam", "its", "mr", "mrs", "ms", "dr",
    "sir", "team", "xx", "xxx", "x",
)
AFFIX_SUFFIXES = (
    "official", "real", "dev", "devs", "hq", "tv", "yt", "ttv", "live", "gg",
    "pro", "prime", "xxx", "xx", "x", "music", "art", "codes", "code",
)
# Separators platforms actually allow in handles.
SEPARATORS = ("", ".", "_", "-")

# Corporate email shapes, roughly ordered by real-world frequency.
EMAIL_PATTERNS = (
    "{first}.{last}", "{first}{last}", "{f}{last}", "{first}_{last}",
    "{first}", "{last}", "{first}-{last}", "{f}.{last}", "{first}{l}",
    "{last}.{first}", "{last}{first}", "{last}{f}", "{f}{l}", "{last}_{first}",
    "{first}.{m}.{last}", "{f}{m}{last}", "{first}{m}{last}",
)


def _ascii_fold(text: str) -> str:
    """Fold accents/diacritics to ASCII: 'Çağan Çalıdağ' -> 'cagan calidag'.

    Handles the Turkish dotless-i and soft-g, German eszett, and Nordic letters
    explicitly, because the generic NFKD path drops them rather than
    transliterating — which would silently mangle the name.
    """
    pre = (text.replace("ı", "i").replace("İ", "I").replace("ğ", "g")
               .replace("Ğ", "G").replace("ş", "s").replace("Ş", "S")
               .replace("ß", "ss").replace("ø", "o").replace("Ø", "O")
               .replace("æ", "ae").replace("Æ", "AE").replace("ð", "d")
               .replace("þ", "th").replace("ł", "l").replace("Ł", "L"))
    return "".join(c for c in unicodedata.normalize("NFKD", pre)
                   if not unicodedata.combining(c))


def split_name(full_name: str) -> dict[str, object]:
    """Split a display name into parts.

    Accepts "First Last", "First Middle Last", "Last, First", and accented or
    Turkish spellings. Surname particles (van, de, bin, al, ...) stay attached to
    the surname, because that is how they show up in handles and addresses.

    Args:
        full_name: A human name as written.

    Returns:
        ``{"first", "middle": [...], "last", "parts": [...], "raw"}`` — all
        lowercase ASCII. ``last`` is "" for a single-token name.

    Raises:
        ValueError: If no usable name characters are present.
    """
    raw = full_name.strip()
    if "," in raw:  # "Calidag, Cagan Efe" -> "Cagan Efe Calidag"
        last_part, _, rest = raw.partition(",")
        raw = f"{rest.strip()} {last_part.strip()}"
    tokens = [t for t in re.split(r"[^a-z0-9]+", _ascii_fold(raw).lower()) if t]
    if not tokens:
        raise ValueError(f"no usable name parts in {full_name!r}")

    particles = {"van", "von", "de", "der", "den", "del", "della", "di", "da",
                 "dos", "du", "la", "le", "el", "al", "bin", "ibn", "binti",
                 "mac", "mc", "st", "ter", "ten", "op", "aan", "zu", "af", "av",
                 "abu", "ben", "san", "santa", "dello", "delle"}
    # Fold a trailing particle run into the surname:
    # ["jan","van","der","berg"] -> last="vanderberg".
    last, cut = "", len(tokens)
    if len(tokens) > 1:
        i = len(tokens) - 1
        while i > 1 and tokens[i - 1] in particles:
            i -= 1
        last, cut = "".join(tokens[i:]), i
    return {"first": tokens[0], "middle": tokens[1:cut] if cut > 1 else [],
            "last": last, "parts": tokens, "raw": full_name.strip()}


def name_key(full_name: str) -> frozenset[str]:
    """The comparable form of a name: ASCII-folded, lowercased token set.

    ``"Çağan Efe Çalıdağ"`` and ``"cagan calidag"`` both reduce to token sets
    that overlap, which is what lets :func:`name_matches` recognize them as the
    same person written two ways.
    """
    return frozenset(t for t in re.split(r"[^a-z0-9]+", _ascii_fold(full_name).lower())
                     if len(t) > 1)


def name_matches(a: str, b: str) -> dict[str, object]:
    """Decide whether two written names plausibly denote the same person.

    Handles the cases that actually occur: diacritics dropped or kept
    (Çağan/Cagan), a middle name present on one side only, surname-first order,
    and initials standing in for a full given name.

    Args:
        a: One spelling.
        b: The other.

    Returns:
        ``{"match": bool, "relation": str, "shared": [...], "extra_a": [...],
        "extra_b": [...]}`` where ``relation`` is one of ``exact``,
        ``superset`` (b adds names, e.g. a middle name), ``subset``,
        ``initial``, ``partial`` or ``none``.
    """
    ta, tb = name_key(a), name_key(b)
    if not ta or not tb:
        return {"match": False, "relation": "none", "shared": [],
                "extra_a": sorted(ta), "extra_b": sorted(tb)}
    shared = ta & tb
    out = {"shared": sorted(shared), "extra_a": sorted(ta - tb),
           "extra_b": sorted(tb - ta)}
    if ta == tb:
        return {**out, "match": True, "relation": "exact"}
    if ta < tb:
        # "Cagan Calidag" inside "Cagan Efe Calidag" -> the longer one is fuller.
        return {**out, "match": True, "relation": "superset"}
    if tb < ta:
        return {**out, "match": True, "relation": "subset"}
    # Initials: every unmatched token on one side is the first letter of an
    # unmatched token on the other ("C. Calidag" vs "Cagan Calidag").
    if shared:
        rest_a, rest_b = ta - tb, tb - ta
        if rest_a and all(len(x) == 1 and any(y.startswith(x) for y in rest_b)
                          for x in rest_a):
            return {**out, "match": True, "relation": "initial"}
        if rest_b and all(len(x) == 1 and any(y.startswith(x) for y in rest_a)
                          for x in rest_b):
            return {**out, "match": True, "relation": "initial"}
        # At least two shared tokens (given + family) is a real match even when
        # both sides carry extra names.
        if len(shared) >= 2:
            return {**out, "match": True, "relation": "partial"}
    return {**out, "match": False, "relation": "none"}


def fuller_name(current: str, candidate: str) -> str:
    """Return whichever spelling is the better label for the same person.

    Prefers more name tokens (a middle name is real information), then the
    spelling that kept its diacritics — ``Çağan Efe Çalıdağ`` is the person's
    actual name and ``cagan calidag`` is a transliteration of it.
    """
    if not candidate.strip():
        return current
    if not current.strip():
        return candidate
    if not name_matches(current, candidate)["match"]:
        return current
    ca, cb = name_key(current), name_key(candidate)
    if len(cb) != len(ca):
        return candidate if len(cb) > len(ca) else current
    a_marks = sum(1 for ch in current if _ascii_fold(ch) != ch)
    b_marks = sum(1 for ch in candidate if _ascii_fold(ch) != ch)
    if b_marks != a_marks:
        return candidate if b_marks > a_marks else current
    # Same information both ways: prefer the properly capitalized rendering.
    return candidate if candidate.istitle() and not current.istitle() else current


def strip_affixes(handle: str) -> dict[str, object]:
    """Strip decoration from a handle to expose its core, deterministically.

    ``xX_dave_Xx`` -> ``dave``; ``realdave1994`` -> ``dave`` (+ digits 1994).
    Reports every layer removed so a caller can see whether it went too far.

    Args:
        handle: The raw handle.

    Returns:
        ``{"core", "removed": [...], "digits": [...]}``. ``digits`` holds
        leading/trailing number runs — often a birth year, so worth feeding to a
        DoB hypothesis, but never fact on its own.
    """
    h = handle.strip().lstrip("@").lower()
    removed: list[str] = []
    digits: list[str] = []

    changed = True
    while changed and len(h) > 2:
        changed = False
        if (h2 := h.strip("._-")) != h:
            h, changed = h2, True
        if (m := re.match(r"^(\d{1,4})(?=[a-z])", h)) and len(h) - len(m.group(1)) > 2:
            digits.append(m.group(1))
            h, changed = h[m.end():], True
        if (m := re.search(r"(\d{1,4})$", h)) and len(h) - len(m.group(1)) > 2:
            digits.append(m.group(1))
            h, changed = h[: m.start()], True
        for pre in sorted(AFFIX_PREFIXES, key=len, reverse=True):
            if h.startswith(pre) and len(h) - len(pre) > 2:
                removed.append(pre)
                h, changed = h[len(pre):], True
                break
        for suf in sorted(AFFIX_SUFFIXES, key=len, reverse=True):
            if h.endswith(suf) and len(h) - len(suf) > 2:
                removed.append(suf)
                h, changed = h[: -len(suf)], True
                break
    return {"core": h.strip("._-"), "removed": removed, "digits": digits}


def handles_from_name(
    full_name: str,
    *,
    separators: tuple[str, ...] = SEPARATORS,
    include_years: tuple[int, ...] = (),
    limit: int = 200,
) -> list[str]:
    """Enumerate the handles a name can produce, most-likely first.

    Covers the shapes people actually use: full concatenation
    (``cagancalidag``), middle-name inclusion (``caganefecalidag``), truncation
    (``caganc``), initial+surname (``ccalidag``), separator variants, reversed
    order, and first- or last-name alone.

    Args:
        full_name: Name as written; accents and Turkish letters are folded.
        separators: Separators to interleave ("", ".", "_", "-").
        include_years: Numbers to append as suffixes, e.g. ``(1998, 98)``. Pass
            these only when you have a reason to — they multiply the list.
        limit: Maximum candidates returned.

    Returns:
        De-duplicated handle strings, best first.

    Raises:
        ValueError: If the name has no usable parts.
    """
    n = split_name(full_name)
    first, last = str(n["first"]), str(n["last"])
    middles = [str(m) for m in n["middle"]]  # type: ignore[union-attr]
    f, l = first[:1], last[:1]

    out: list[str] = []

    def add(*cands: str) -> None:
        for c in cands:
            c = c.strip("._-")
            if len(c) >= 2 and c not in out:
                out.append(c)

    # Ordered by how obvious the form is, because callers sweep the top of this
    # list first. Full spellings of the name come before ANY abbreviation:
    # "cagancalidag" and "caganefecalidag" are what people actually register;
    # "cc" and "cagancal" are long shots that used to crowd them out.

    # 1. the whole name, written out
    if first and last:
        for s in separators:
            add(f"{first}{s}{last}")              # cagancalidag, cagan.calidag
    for mid in middles:
        if first and last:
            for s in separators:
                add(f"{first}{s}{mid}{s}{last}")  # caganefecalidag
    # 2. other full-word pairings
    for mid in middles:
        if last:
            for s in separators:
                add(f"{mid}{s}{last}")            # efecalidag
        if first:
            add(f"{first}{mid}")                  # caganefe
    if first and last:
        for s in separators:
            add(f"{last}{s}{first}")              # calidagcagan
    # 3. single full words
    if first:
        add(first)
    if last:
        add(last)
    # 4. one part abbreviated to an initial
    if first and last:
        for s in separators:
            add(f"{f}{s}{last}")                  # ccalidag
        for s in separators:
            add(f"{first}{s}{l}")                 # caganc
        for mid in middles:
            add(f"{f}{mid}{last}", f"{first}{mid[:1]}{last}")
        add(f"{last}{f}")
    # 5. truncations and initials — last resort
    if first and last:
        for k in range(2, min(4, len(last)) + 1):
            add(f"{first}{last[:k]}")             # caganca, cagancal
        for k in range(2, min(5, len(first)) + 1):
            add(f"{first[:k]}{last}")             # cacalidag, cagcalidag
        add(f"{f}{l}")

    for y in include_years:
        for base in list(out)[:10]:
            add(f"{base}{y}", f"{base}_{y}")
    return out[:limit]


def email_candidates(
    full_name: str,
    domain: str,
    *,
    patterns: tuple[str, ...] = EMAIL_PATTERNS,
    limit: int = 40,
) -> list[str]:
    """Build likely email addresses for a person at a domain.

    Standard corporate-format permutation. These are HYPOTHESES: nothing here
    checks that an address exists, and this package never runs SMTP probes to
    find out (see :mod:`osint.email`). Use them as search terms, or match them
    against addresses recovered from git history and breach data — one confirmed
    hit reveals the format the whole organization uses.

    Args:
        full_name: The person's name.
        domain: Mail domain (a URL or ``@domain`` form is accepted).
        patterns: Format strings over ``{first} {last} {f} {l} {m}``.
        limit: Maximum addresses returned.

    Returns:
        De-duplicated addresses, most-likely first.

    Raises:
        ValueError: If the name or domain is unusable.
    """
    n = split_name(full_name)
    dom = re.sub(r"^[a-z]+://", "", domain.strip().lower()).lstrip("@")
    dom = dom.split("/")[0].split(":")[0].strip(".")
    if "." not in dom:
        raise ValueError(f"not a valid mail domain: {domain!r}")

    first, last = str(n["first"]), str(n["last"])
    middles = [str(m) for m in n["middle"]]  # type: ignore[union-attr]
    fields = {"first": first, "last": last or first, "f": first[:1],
              "l": (last or first)[:1], "m": middles[0][:1] if middles else ""}
    out: list[str] = []
    for pat in patterns:
        local = re.sub(r"[._-]{2,}", ".", pat.format(**fields)).strip("._-")
        if local and (addr := f"{local}@{dom}") not in out:
            out.append(addr)
    return out[:limit]


def run(
    *,
    name: str = "",
    handle: str = "",
    email_domain: str = "",
    years: tuple[int, ...] = (),
    limit: int = 200,
) -> dict:
    """Expand a seed into candidate identity strings.

    Args:
        name: A full name to expand into handles (and emails, with a domain).
        handle: A handle to normalize (affix/digit stripping only).
        email_domain: With ``name``, also build email candidates.
        years: Numeric suffixes to append to handles.
        limit: Cap on the handle list.

    Returns:
        ``{"seed_name", "seed_handle", "name_parts", "handles", "normalized",
        "emails", "next_steps"}``.

    Raises:
        ValueError: If neither ``name`` nor ``handle`` is given.
    """
    if not name and not handle:
        raise ValueError("give a name, a handle, or both")

    res: dict = {"seed_name": name, "seed_handle": handle, "name_parts": {},
                 "handles": [], "normalized": {}, "emails": [], "next_steps": []}
    if name:
        res["name_parts"] = split_name(name)
        res["handles"] = handles_from_name(name, include_years=years, limit=limit)
        if email_domain:
            res["emails"] = email_candidates(name, email_domain)
    if handle:
        res["normalized"] = strip_affixes(handle)

    res["next_steps"] = [
        "Pick the 5-15 handles that look plausible — do not sweep all of them.",
        "Feed that edited list to osint.username (it takes multiple handles).",
        "For each hit, run osint.profile on the URL to recover the real name, "
        "then come back here with the corrected spelling.",
        "If you are holding a run-together handle, read the name out of it "
        "yourself and pass it as --name; this tool does not guess splits.",
    ]
    return res


def _compact_lines(res: dict) -> list[str]:
    lines: list[str] = []
    if res["name_parts"]:
        n = res["name_parts"]
        lines.append(f"# name: first={n['first']} "
                     f"middle={' '.join(n['middle']) or '-'} last={n['last']}")
    if res["handles"]:
        lines.append(f"## HANDLE CANDIDATES ({len(res['handles'])}, best first)")
        lines.append("  " + ", ".join(res["handles"]))
    if res["normalized"]:
        a = res["normalized"]
        lines.append(f"## NORMALIZED {res['seed_handle']} -> {a['core']}")
        lines.append(f"  removed={a['removed'] or '-'}  digits={a['digits'] or '-'}"
                     f"{'  (digits may be a birth year)' if a['digits'] else ''}")
    if res["emails"]:
        lines.append(f"## EMAIL CANDIDATES ({len(res['emails'])}) — hypotheses, unverified")
        lines += [f"  {e}" for e in res["emails"]]
    lines.append("## NEXT")
    lines += [f"  - {s}" for s in res["next_steps"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.variants",
        description="Expand known name parts into handle and email candidates.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.variants --name "Cagan Efe Calidag"\n'
                '  python -m osint.variants --name "Ada Lovelace" '
                '--email-domain example.com --json\n'
                '  python -m osint.variants --handle xX_realdave1994_Xx\n'),
    )
    p.add_argument("--name", default="", help="Full name to expand into handles/emails.")
    p.add_argument("--handle", default="", help="Handle to normalize (strip affixes/digits).")
    p.add_argument("--email-domain", default="", help="Build email candidates at this domain.")
    p.add_argument("--years", default="",
                   help="Comma-separated numeric suffixes to try, e.g. 1998,98.")
    p.add_argument("--limit", type=int, default=200, help="Cap on handles (default 200).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.name and not args.handle:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(name=args.name, handle=args.handle, email_domain=args.email_domain,
                  years=tuple(int(y) for y in re.findall(r"\d+", args.years)),
                  limit=args.limit)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
