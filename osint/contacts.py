"""Extract and validate phone numbers and postal addresses from text and markup.

Free-text phone and address extraction is mostly a false-positive problem. Any
regex loose enough to catch ``+90 (532) 123 45 67`` also catches order numbers,
timestamps, ISBNs, prices, version strings and CSS pixel values. So nothing here
returns a bare regex match: every candidate is normalized, length-checked
against the E.164 rules, matched against the real country calling-code table,
screened for the shapes that are never phone numbers, and scored by the words
around it. Callers get a confidence level and the reason for it.

Addresses come from three places, best first:
    1. schema.org ``PostalAddress`` in JSON-LD — already structured, unambiguous
    2. microformats/vCard class names (``street-address``, ``postal-code``, ...)
    3. free text matched against per-country postcode + street patterns

No third-party dependencies. libphonenumber would be more accurate for national
number plans, but pulling in a metadata blob for this is not worth it; the
country/type detection here is derived from the calling-code table plus a few
national prefixes, and anything uncertain is labelled as such rather than
guessed.

Safety: pure computation on text you already fetched. No network, no I/O.

Usage:
    python -m osint.contacts --text "call me on +90 532 123 45 67"
    python -m osint.contacts --file page.html --region TR --json
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys

from common.output import emit

# ITU-T E.164 country calling codes, longest-prefix matched. Trimmed to real
# assignments; NANP (+1) countries collapse to "NANP" since the code alone
# cannot distinguish US from Canada.
CALLING_CODES: dict[str, str] = {
    "1": "NANP (US/Canada/Caribbean)", "7": "Russia/Kazakhstan",
    "20": "Egypt", "27": "South Africa", "30": "Greece", "31": "Netherlands",
    "32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary",
    "39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria",
    "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway",
    "48": "Poland", "49": "Germany", "51": "Peru", "52": "Mexico",
    "53": "Cuba", "54": "Argentina", "55": "Brazil", "56": "Chile",
    "57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia",
    "62": "Indonesia", "63": "Philippines", "64": "New Zealand",
    "65": "Singapore", "66": "Thailand", "81": "Japan", "82": "South Korea",
    "84": "Vietnam", "86": "China", "90": "Türkiye", "91": "India",
    "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar",
    "98": "Iran", "212": "Morocco", "213": "Algeria", "216": "Tunisia",
    "218": "Libya", "220": "Gambia", "221": "Senegal", "223": "Mali",
    "225": "Côte d'Ivoire", "226": "Burkina Faso", "227": "Niger",
    "228": "Togo", "229": "Benin", "230": "Mauritius", "231": "Liberia",
    "232": "Sierra Leone", "233": "Ghana", "234": "Nigeria", "235": "Chad",
    "236": "Central African Republic", "237": "Cameroon", "238": "Cape Verde",
    "240": "Equatorial Guinea", "241": "Gabon", "242": "Congo",
    "243": "DR Congo", "244": "Angola", "245": "Guinea-Bissau",
    "248": "Seychelles", "249": "Sudan", "250": "Rwanda", "251": "Ethiopia",
    "252": "Somalia", "253": "Djibouti", "254": "Kenya", "255": "Tanzania",
    "256": "Uganda", "257": "Burundi", "258": "Mozambique", "260": "Zambia",
    "261": "Madagascar", "263": "Zimbabwe", "264": "Namibia", "265": "Malawi",
    "266": "Lesotho", "267": "Botswana", "268": "Eswatini", "269": "Comoros",
    "290": "Saint Helena", "291": "Eritrea", "297": "Aruba", "298": "Faroe Islands",
    "299": "Greenland", "350": "Gibraltar", "351": "Portugal", "352": "Luxembourg",
    "353": "Ireland", "354": "Iceland", "355": "Albania", "356": "Malta",
    "357": "Cyprus", "358": "Finland", "359": "Bulgaria", "370": "Lithuania",
    "371": "Latvia", "372": "Estonia", "373": "Moldova", "374": "Armenia",
    "375": "Belarus", "376": "Andorra", "377": "Monaco", "378": "San Marino",
    "380": "Ukraine", "381": "Serbia", "382": "Montenegro", "383": "Kosovo",
    "385": "Croatia", "386": "Slovenia", "387": "Bosnia and Herzegovina",
    "389": "North Macedonia", "420": "Czechia", "421": "Slovakia",
    "423": "Liechtenstein", "500": "Falkland Islands", "501": "Belize",
    "502": "Guatemala", "503": "El Salvador", "504": "Honduras",
    "505": "Nicaragua", "506": "Costa Rica", "507": "Panama", "509": "Haiti",
    "590": "Guadeloupe", "591": "Bolivia", "592": "Guyana", "593": "Ecuador",
    "595": "Paraguay", "597": "Suriname", "598": "Uruguay", "670": "Timor-Leste",
    "672": "Norfolk Island", "673": "Brunei", "674": "Nauru", "675": "Papua New Guinea",
    "676": "Tonga", "677": "Solomon Islands", "678": "Vanuatu", "679": "Fiji",
    "680": "Palau", "682": "Cook Islands", "685": "Samoa", "686": "Kiribati",
    "689": "French Polynesia", "690": "Tokelau", "691": "Micronesia",
    "692": "Marshall Islands", "850": "North Korea", "852": "Hong Kong",
    "853": "Macau", "855": "Cambodia", "856": "Laos", "880": "Bangladesh",
    "886": "Taiwan", "960": "Maldives", "961": "Lebanon", "962": "Jordan",
    "963": "Syria", "964": "Iraq", "965": "Kuwait", "966": "Saudi Arabia",
    "967": "Yemen", "968": "Oman", "970": "Palestine", "971": "UAE",
    "972": "Israel", "973": "Bahrain", "974": "Qatar", "975": "Bhutan",
    "976": "Mongolia", "977": "Nepal", "992": "Tajikistan", "993": "Turkmenistan",
    "994": "Azerbaijan", "995": "Georgia", "996": "Kyrgyzstan", "998": "Uzbekistan",
}
# ISO code -> (calling code, national trunk prefix, national significant length)
REGIONS: dict[str, tuple[str, str, tuple[int, ...]]] = {
    "TR": ("90", "0", (10,)), "US": ("1", "1", (10,)), "CA": ("1", "1", (10,)),
    "GB": ("44", "0", (10, 9)), "DE": ("49", "0", (10, 11, 9)),
    "FR": ("33", "0", (9,)), "NL": ("31", "0", (9,)), "ES": ("34", "", (9,)),
    "IT": ("39", "", (9, 10)), "SE": ("46", "0", (9,)), "IN": ("91", "0", (10,)),
    "AU": ("61", "0", (9,)), "JP": ("81", "0", (10,)), "BR": ("55", "0", (10, 11)),
}

# Candidate finder. Deliberately flat — no nested quantifiers, so it cannot
# backtrack catastrophically on a long run of digits.
_PHONE_CANDIDATE = re.compile(r"(?:\+|00)?\d[\d\s().\-/]{5,22}\d")
# Words near a number that make it much more likely to be a phone number.
# Kept specific: "no" and "ara" were here for Turkish, but "no" matches ordinary
# English prose ("no label nearby") and turned every number into a high-
# confidence hit. "no" is an ADDRESS marker in Turkish anyway, not a phone one.
_PHONE_CONTEXT = re.compile(
    r"(?i)\b(tel|telephone|phone|mobile|mob|cell|call|whats\s?app|whatsapp|"
    r"fax|gsm|contact|hotline|telefon|cep\s?tel|numara|arayin)\b")
# Shapes that are never phone numbers, checked against the raw matched text.
# Written as a plain alternation on purpose: in re.VERBOSE a '#' comment runs to
# the next REAL newline, and this pattern is built by string concatenation with
# no real newlines in it — so verbose mode would comment out the whole thing.
_NOT_PHONE = re.compile(
    r"\d{4}-\d{2}-\d{2}"            # ISO date
    r"|\d{2}[:.]\d{2}[:.]\d{2}"     # timestamp
    r"|\d+\.\d+\.\d+"               # version string or IPv4
    r"|^[\s+]*0{4,}")               # padding, not a number

_ADDRESS_CLASS_RE = re.compile(
    r'class=["\'][^"\']*\b(street-address|locality|region|postal-code|'
    r'country-name|p-adr|h-adr|adr)\b[^"\']*["\'][^>]*>(.*?)<', re.I | re.S)

# Per-country postcode shapes, used to anchor a free-text address match.
POSTCODE_PATTERNS: dict[str, str] = {
    "GB": r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b",
    "US": r"\b\d{5}(?:-\d{4})?\b",
    "TR": r"\b\d{5}\b",
    "DE": r"\b\d{5}\b",
    "NL": r"\b\d{4}\s?[A-Z]{2}\b",
    "FR": r"\b\d{5}\b",
    "CA": r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b",
}
_STREET_WORDS = (
    r"street|st\.|road|rd\.|avenue|ave\.|boulevard|blvd|lane|ln\.|drive|dr\.|"
    r"court|ct\.|place|pl\.|square|sq\.|way|highway|parkway|suite|apt|apartment|"
    r"floor|building|block|unit|po box|"
    r"sokak|sok\.|cadde|cad\.|mahalle|mah\.|bulvar|blv\.|apt\.|daire|kat|no:|"
    r"straße|strasse|str\.|platz|weg|allee|"
    r"rue|avenue|boulevard|place|"
    r"calle|avenida|plaza"
)
# One leading (?i): an inline global flag is only legal at the start of a
# pattern, and this is assembled from two alternatives.
_STREET_RE = re.compile(
    rf"(?i)\b\d{{1,5}}[a-z]?\s+[\w.'\-]+(?:\s+[\w.'\-]+){{0,4}}\s+(?:{_STREET_WORDS})\b"
    rf"|\b[\w.'\-]+(?:\s+[\w.'\-]+){{0,3}}\s+(?:{_STREET_WORDS})\s*(?:no[:.]?\s*)?\d{{1,5}}\b")


def normalize_phone(raw: str, *, region: str = "") -> dict | None:
    """Normalize one candidate string into a validated phone number.

    Args:
        raw: The matched text, e.g. ``"+90 (532) 123 45 67"``.
        region: ISO-3166 code (``TR``, ``GB``, ...) to assume for numbers written
            in national format without a country code.

    Returns:
        ``{"e164","digits","country","country_code","national","kind"}`` or None
        if the candidate can't be a real phone number.
    """
    if _NOT_PHONE.search(raw):
        return None
    has_plus = raw.strip().startswith("+") or raw.strip().startswith("00")
    digits = re.sub(r"\D", "", raw)
    if raw.strip().startswith("00"):
        digits = digits[2:]
    if not 7 <= len(digits) <= 15:      # E.164 allows at most 15 digits
        return None
    if len(set(digits)) <= 2:           # 0000000, 1212121212 -> not a number
        return None

    cc, country, national = "", "", digits
    if has_plus:
        for size in (3, 2, 1):          # longest-prefix match
            if digits[:size] in CALLING_CODES:
                cc, country = digits[:size], CALLING_CODES[digits[:size]]
                national = digits[size:]
                break
        if not cc:
            return None                 # a + with no valid country code is noise
    elif region.upper() in REGIONS:
        cc, trunk, lengths = REGIONS[region.upper()]
        country = CALLING_CODES.get(cc, region.upper())
        national = digits[len(trunk):] if trunk and digits.startswith(trunk) else digits
        if lengths and len(national) not in lengths:
            return None
    else:
        return None                     # no country code and no region: unusable

    if not 4 <= len(national) <= 14:
        return None

    kind = ""
    if country == "Türkiye" and national.startswith("5"):
        kind = "mobile"
    elif country == "United Kingdom" and national.startswith("7"):
        kind = "mobile"
    elif country.startswith("NANP") and len(national) == 10:
        kind = "fixed or mobile (NANP does not distinguish)"
    return {"e164": f"+{cc}{national}", "digits": digits, "country": country,
            "country_code": f"+{cc}", "national": national, "kind": kind}


def phones(text: str, *, region: str = "", min_confidence: str = "low") -> list[dict]:
    """Find phone numbers in free text.

    Args:
        text: Plain text (run HTML through ``profile._text_of`` first).
        region: ISO code assumed for numbers written without a country code.
            Even with it, a national-format number is only reported when a phone
            word ("tel", "mobile", "whatsapp", ...) sits near it — a bare digit
            run is an id or a price far more often than a phone number.
        min_confidence: ``low``/``medium``/``high`` filter.

    Returns:
        De-duplicated numbers, highest confidence first, each with ``context``
        (the surrounding words) so a human can sanity-check it.
    """
    order = {"high": 3, "medium": 2, "low": 1}
    floor = order.get(min_confidence, 1)
    found: dict[str, dict] = {}

    for m in _PHONE_CANDIDATE.finditer(text):
        raw = m.group(0)
        info = normalize_phone(raw, region=region)
        if not info:
            continue
        window = text[max(0, m.start() - 60):m.end() + 30]
        has_context = bool(_PHONE_CONTEXT.search(window))
        explicit_cc = raw.strip().startswith(("+", "00"))

        if explicit_cc and has_context:
            conf = "high"
        elif explicit_cc or has_context:
            conf = "medium"
        else:
            conf = "low"
        # A bare digit run with neither a country code nor a nearby phone word is
        # not evidence of anything: web pages are full of 10-digit ids, prices
        # and counters, and `region` would happily turn each one into a national
        # number. Require at least one real signal.
        if not explicit_cc and not has_context:
            continue
        if order[conf] < floor:
            continue

        entry = {**info, "raw": raw.strip(), "confidence": conf,
                 "context": re.sub(r"\s+", " ", window).strip()[:160]}
        prev = found.get(info["e164"])
        if not prev or order[conf] > order[prev["confidence"]]:
            found[info["e164"]] = entry

    return sorted(found.values(), key=lambda p: (-order[p["confidence"]], p["e164"]))


def addresses_from_jsonld(nodes: list[dict]) -> list[dict]:
    """Pull schema.org PostalAddress objects out of parsed JSON-LD nodes."""
    out: list[dict] = []

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            if str(node.get("@type", "")).endswith("PostalAddress"):
                parts = {
                    "street": str(node.get("streetAddress", "") or ""),
                    "locality": str(node.get("addressLocality", "") or ""),
                    "region": str(node.get("addressRegion", "") or ""),
                    "postal_code": str(node.get("postalCode", "") or ""),
                    "country": str(node.get("addressCountry", "") or "")
                    if not isinstance(node.get("addressCountry"), dict)
                    else str(node["addressCountry"].get("name", "")),
                }
                if any(parts.values()):
                    out.append({**parts, "source": "json-ld PostalAddress",
                                "confidence": "high",
                                "formatted": ", ".join(v for v in parts.values() if v)})
            for value in node.values():
                walk(value)

    walk(nodes)
    return out


def addresses_from_microformats(page_html: str) -> list[dict]:
    """Pull h-adr / vCard address fields out of class-annotated markup."""
    parts: dict[str, str] = {}
    for cls, value in _ADDRESS_CLASS_RE.findall(page_html):
        text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", value))).strip()
        if not text:
            continue
        key = {"street-address": "street", "locality": "locality", "region": "region",
               "postal-code": "postal_code", "country-name": "country"}.get(cls.lower())
        if key and key not in parts:
            parts[key] = text
    if not parts:
        return []
    full = {"street": "", "locality": "", "region": "", "postal_code": "",
            "country": "", **parts}
    return [{**full, "source": "microformats h-adr", "confidence": "high",
             "formatted": ", ".join(v for v in full.values() if v)}]


def _postcode_countries(matched: str, codes: tuple[str, ...]) -> list[str]:
    """Every country in ``codes`` whose postcode shape fits the matched text.

    Tested against the matched STRING, not against the pattern that happened to
    find it: "62704" fits the US, Turkish, German and French shapes, so calling
    it American would invent precision. "NW1 6XE" fits only the UK, and
    "12345-6789" only the US — those stay unambiguous.
    """
    return [c for c in codes
            if re.fullmatch(POSTCODE_PATTERNS[c], matched.strip())]


def addresses_from_text(
    text: str,
    *,
    countries: tuple[str, ...] = (),
    region: str = "",
) -> list[dict]:
    """Find address-shaped strings in free text.

    Requires BOTH a street-like phrase and a nearby postcode before reporting
    anything — either alone produces far too many false positives (every "Suite"
    in a footer, every 5-digit number on a page).

    Args:
        text: Plain text.
        countries: ISO codes whose postcode patterns to try. Defaults to all.
        region: ISO code to try first and to prefer when several countries share
            a postcode shape.

    Returns:
        Candidate addresses, each with the matched fragment, the countries the
        postcode shape is consistent with, and a medium confidence.
    """
    out: list[dict] = []
    seen: set[str] = set()
    codes = countries or tuple(POSTCODE_PATTERNS)
    if region and region.upper() in POSTCODE_PATTERNS:
        codes = (region.upper(),) + tuple(c for c in codes if c != region.upper())

    for m in _STREET_RE.finditer(text):
        window = text[m.start():m.end() + 120]
        # Take the NEAREST postcode across all patterns, not the first country in
        # dict order: scanning per-country would pair a London street with a
        # Turkish postcode 80 characters later.
        best: tuple[int, int, str, str] | None = None
        for cc in codes:
            pm = re.search(POSTCODE_PATTERNS[cc], window)
            if pm and (best is None or pm.start() < best[0]):
                best = (pm.start(), pm.end(), POSTCODE_PATTERNS[cc], pm.group(0))
        if best is None:
            continue
        _, end, pattern, code_text = best

        # `end` is relative to the window, which starts at m.start().
        frag = re.sub(r"\s+", " ", text[m.start():m.start() + end]).strip()
        # The street pattern can swallow a few preceding words. Strip leading
        # sentences while the remainder still holds a street AND the postcode.
        while True:
            trimmed = re.sub(r"^.*?[.!?]\s+", "", frag)
            if (trimmed and trimmed != frag and re.search(pattern, trimmed)
                    and _STREET_RE.search(trimmed)):
                frag = trimmed
            else:
                break

        key = re.sub(r"[^a-z0-9]", "", frag.lower())
        # A fragment that is only the postcode is not an address; the trimming
        # loop can strip a street away when the sentence break falls badly.
        if (not key or key in seen or len(frag) > 200 or len(frag) < 12
                or not _STREET_RE.search(frag)):
            continue
        seen.add(key)
        consistent = _postcode_countries(code_text, codes) or [cc]
        label = (consistent[0] if len(consistent) == 1
                 else f"{'/'.join(sorted(consistent))} (shape is ambiguous)")
        out.append({"street": m.group(0).strip(), "locality": "", "region": "",
                    "postal_code": code_text.strip(), "country": label,
                    "country_candidates": sorted(consistent),
                    "source": "free text (postcode shape match)",
                    "confidence": "medium", "formatted": frag})
    return out


def run(
    text: str = "",
    page_html: str = "",
    jsonld: list[dict] | None = None,
    *,
    region: str = "",
    countries: tuple[str, ...] = (),
) -> dict:
    """Extract phones and addresses from whatever representation you have.

    Args:
        text: Plain text (best for phones).
        page_html: Raw HTML (enables microformats extraction).
        jsonld: Already-parsed JSON-LD nodes (best for addresses).
        region: ISO code for national-format phone numbers; also used to
            prefer that country when a postcode shape is ambiguous.
        countries: ISO codes for postcode matching.

    Returns:
        ``{"phones": [...], "addresses": [...]}`` — addresses ordered
        high-confidence (structured) first.
    """
    addrs = addresses_from_jsonld(jsonld or [])
    if page_html:
        addrs += addresses_from_microformats(page_html)
    if text:
        addrs += addresses_from_text(text, countries=countries, region=region)

    # Drop any candidate wholly contained in another: overlapping street matches
    # produce a long fragment and a tighter one for the same address; keep the
    # tighter, and prefer structured sources over free text.
    order = {"high": 0, "medium": 1, "low": 2}
    addrs.sort(key=lambda a: (order.get(a["confidence"], 3), len(a["formatted"])))
    deduped: dict[str, dict] = {}
    kept: list[str] = []
    for a in addrs:
        norm = re.sub(r"[^a-z0-9]", "", a["formatted"].lower())
        if not norm or any(norm in k or k in norm for k in kept):
            continue
        kept.append(norm)
        deduped[norm[:80]] = a
    return {"phones": phones(text, region=region) if text else [],
            "addresses": sorted(deduped.values(),
                                key=lambda a: order.get(a["confidence"], 3))}


def _compact_lines(res: dict) -> list[str]:
    lines = []
    if res["phones"]:
        lines.append(f"## PHONE NUMBERS ({len(res['phones'])})")
        for p in res["phones"]:
            kind = f"  [{p['kind']}]" if p["kind"] else ""
            lines.append(f"  {p['e164']:<18} {p['country']:<26} {p['confidence']}{kind}")
            lines.append(f"      raw: {p['raw']}   ...{p['context'][:100]}")
    else:
        lines.append("## PHONE NUMBERS (none)")
    if res["addresses"]:
        lines.append(f"## ADDRESSES ({len(res['addresses'])})")
        for a in res["addresses"]:
            lines.append(f"  [{a['confidence']}] {a['formatted']}")
            lines.append(f"      via {a['source']}")
    else:
        lines.append("## ADDRESSES (none)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.contacts",
        description="Extract and validate phone numbers and postal addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.contacts --text "call +90 532 123 45 67"\n'
                '  python -m osint.contacts --file page.html --region TR --json\n'
                '\nWithout --region, numbers written without a country code are\n'
                'skipped rather than guessed at.\n'),
    )
    p.add_argument("--text", default="", help="Text to scan.")
    p.add_argument("--file", default="", help="File to scan (HTML is handled).")
    p.add_argument("--region", default="",
                   help="ISO code assumed for national-format numbers (TR, GB, US...).")
    p.add_argument("--countries", default="",
                   help="Comma-separated ISO codes for postcode matching.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.text or args.file):
        parser.print_help(sys.stderr)
        return 2

    raw = args.text
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    from osint import profile as _profile
    is_html = "<" in raw and ">" in raw
    text = _profile._text_of(raw) if is_html else raw
    nodes = _profile._json_ld(raw) if is_html else []
    res = run(text=text, page_html=raw if is_html else "", jsonld=nodes,
              region=args.region,
              countries=tuple(c.strip().upper() for c in args.countries.split(",") if c.strip()))
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
