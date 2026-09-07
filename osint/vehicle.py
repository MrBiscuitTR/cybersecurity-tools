"""Decode vehicles: VIN -> full specification, licence plate -> region and year.

Two capabilities that are genuinely public, plus a clear statement of the one
that isn't.

WHAT THIS DOES

  VIN decoding      A VIN encodes the manufacturer, plant, model year, engine,
                    body, restraint system and more. NHTSA's vPIC database
                    decodes it for free with no key, and it covers most vehicles
                    sold in the US market regardless of where they were built.
                    The check digit is validated locally first, so a typo is
                    caught before a request goes out.
  Recall lookup     Open safety recalls for a make/model/year (NHTSA, free).
  Plate decoding    A plate is not a random string. It encodes the issuing
                    region, and in several countries the registration date:
                      Turkey  first two digits = province (34 = Istanbul)
                      UK      area code + age identifier = the exact half-year
                              the vehicle was first registered
                      Germany 1-3 letter prefix = registration district
                      France  current AA-123-AA format is sequential nationwide;
                              the old system encoded département
                    This runs entirely offline from built-in tables.

WHAT THIS DOES NOT DO — AND WON'T

  Plate -> owner. There is no lawful public API for it anywhere this tool would
  run. In the US, DMV records are protected by the Driver's Privacy Protection
  Act (18 U.S.C. 2721), which restricts disclosure of personal information from
  motor vehicle records to enumerated permissible uses, obtained through the
  state DMV. In the EU/UK it is personal data under the GDPR; in Turkey under
  the KVKK. The "plate lookup" services that advertise otherwise are either
  selling scraped data of dubious provenance or resolving nothing at all.

  If you have a legitimate need for owner details, the routes that actually
  work are: a DMV record request citing a permissible use, a police report, an
  insurance claim, or a subpoena. None of those are an HTTP API, so none of
  them are in this file.

  The UK is a partial exception worth knowing about: the DVLA publishes a free
  Vehicle Enquiry API returning the *vehicle's* tax/MOT status, make, colour and
  engine size from a plate — no owner data. It needs a registered API key
  ($DVLA_API_KEY) and is used here when one is present.

External APIs:
    NHTSA vPIC     https://vpic.nhtsa.dot.gov/api/  (free, no auth)
    NHTSA recalls  https://api.nhtsa.gov/recalls/   (free, no auth)
    DVLA VES       https://driver-vehicle-licensing.api.gov.uk/  ($DVLA_API_KEY)

Safety: read-only. Decodes strings locally and queries government vehicle
databases about the vehicle. Returns no personal data and looks up no person.

Usage:
    python -m osint.vehicle --vin 1HGCM82633A004352
    python -m osint.vehicle --plate "34 ABC 123"
    python -m osint.vehicle --plate "AB12 CDE" --country GB --json
    python -m osint.vehicle --recalls --make Honda --model Accord --year 2003
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from common.output import emit, log
from osint import fetch

# --- Turkey: first two digits of every plate are the province code -----------
TR_PROVINCES = {
    "01": "Adana", "02": "Adıyaman", "03": "Afyonkarahisar", "04": "Ağrı",
    "05": "Amasya", "06": "Ankara", "07": "Antalya", "08": "Artvin",
    "09": "Aydın", "10": "Balıkesir", "11": "Bilecik", "12": "Bingöl",
    "13": "Bitlis", "14": "Bolu", "15": "Burdur", "16": "Bursa",
    "17": "Çanakkale", "18": "Çankırı", "19": "Çorum", "20": "Denizli",
    "21": "Diyarbakır", "22": "Edirne", "23": "Elazığ", "24": "Erzincan",
    "25": "Erzurum", "26": "Eskişehir", "27": "Gaziantep", "28": "Giresun",
    "29": "Gümüşhane", "30": "Hakkâri", "31": "Hatay", "32": "Isparta",
    "33": "Mersin", "34": "İstanbul", "35": "İzmir", "36": "Kars",
    "37": "Kastamonu", "38": "Kayseri", "39": "Kırklareli", "40": "Kırşehir",
    "41": "Kocaeli", "42": "Konya", "43": "Kütahya", "44": "Malatya",
    "45": "Manisa", "46": "Kahramanmaraş", "47": "Mardin", "48": "Muğla",
    "49": "Muş", "50": "Nevşehir", "51": "Niğde", "52": "Ordu", "53": "Rize",
    "54": "Sakarya", "55": "Samsun", "56": "Siirt", "57": "Sinop", "58": "Sivas",
    "59": "Tekirdağ", "60": "Tokat", "61": "Trabzon", "62": "Tunceli",
    "63": "Şanlıurfa", "64": "Uşak", "65": "Van", "66": "Yozgat",
    "67": "Zonguldak", "68": "Aksaray", "69": "Bayburt", "70": "Karaman",
    "71": "Kırıkkale", "72": "Batman", "73": "Şırnak", "74": "Bartın",
    "75": "Ardahan", "76": "Iğdır", "77": "Yalova", "78": "Karabük",
    "79": "Kilis", "80": "Osmaniye", "81": "Düzce",
}

# --- UK: first two letters are the DVLA "memory tag" (issuing region) --------
GB_MEMORY_TAGS = {
    "A": "Anglia (Peterborough/Norwich/Ipswich)", "B": "Birmingham",
    "C": "Cymru (Cardiff/Swansea/Bangor)", "D": "Deeside/Chester/Shrewsbury",
    "E": "Essex (Chelmsford)", "F": "Forest & Fens (Nottingham/Lincoln)",
    "G": "Garden of England (Maidstone/Brighton)", "H": "Hampshire (Bournemouth/Portsmouth)",
    "K": "Luton/Northampton", "L": "London (Wimbledon/Stanmore/Sidcup)",
    "M": "Manchester", "N": "North (Newcastle/Stockton)",
    "O": "Oxford", "P": "Preston (Carlisle)", "R": "Reading",
    "S": "Scotland (Glasgow/Edinburgh/Dundee/Aberdeen/Inverness)",
    "V": "Severn Valley (Worcester)", "W": "West of England (Exeter/Truro/Bristol)",
    "Y": "Yorkshire (Leeds/Sheffield/Beverley)",
}

# --- Germany: 1-3 letter prefix is the registration district (common ones) ---
DE_DISTRICTS = {
    "B": "Berlin", "M": "München", "K": "Köln", "F": "Frankfurt am Main",
    "S": "Stuttgart", "D": "Düsseldorf", "H": "Hannover", "L": "Leipzig",
    "N": "Nürnberg", "E": "Essen", "DO": "Dortmund", "HH": "Hamburg",
    "HB": "Bremen", "MZ": "Mainz", "KA": "Karlsruhe", "MA": "Mannheim",
    "AC": "Aachen", "BN": "Bonn", "DA": "Darmstadt", "DD": "Dresden",
    "DU": "Duisburg", "EF": "Erfurt", "FR": "Freiburg", "GE": "Gelsenkirchen",
    "HD": "Heidelberg", "KI": "Kiel", "KL": "Kaiserslautern", "MD": "Magdeburg",
    "MS": "Münster", "OS": "Osnabrück", "RO": "Rosenheim", "SB": "Saarbrücken",
    "SN": "Schwerin", "UL": "Ulm", "WI": "Wiesbaden", "WÜ": "Würzburg",
}

# VIN transliteration and position weights for the North American check digit.
_VIN_VALUES = {**{str(d): d for d in range(10)},
               **dict(zip("ABCDEFGH", [1, 2, 3, 4, 5, 6, 7, 8])),
               **dict(zip("JKLMNP", [1, 2, 3, 4, 5, 7])),
               **dict(zip("RSTUVWXYZ", [9, 2, 3, 4, 5, 6, 7, 8, 9]))}
_VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
_VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
# Model-year code in VIN position 10. The code repeats on a 30-year cycle
# (letters A..Y for 1980-2000 and again 2010-2030; digits 1..9 for 2001-2009 and
# again 2031-2039), so a code maps to TWO years, not one. Reporting a single
# year here silently mislabels every pre-2010 vehicle.
_VIN_YEAR_LETTERS = "ABCDEFGHJKLMNPRSTVWXY"


def _vin_year_candidates(code: str, *, current_year: int = 2026) -> list[int]:
    """Both model years a position-10 code can mean, minus implausible futures.

    Args:
        code: The 10th VIN character.
        current_year: Used to drop years that haven't happened yet.

    Returns:
        Candidate model years, oldest first (usually one survives the filter).
    """
    if code in _VIN_YEAR_LETTERS:
        i = _VIN_YEAR_LETTERS.index(code)
        cands = [1980 + i, 2010 + i]
    elif code.isdigit() and code != "0":
        i = int(code) - 1
        cands = [2001 + i, 2031 + i]
    else:
        return []
    return [y for y in cands if y <= current_year + 1]


def validate_vin(vin: str) -> dict:
    """Validate a VIN's shape and North American check digit, offline.

    The 9th character is a checksum over the other 16. Vehicles built for some
    non-US markets don't populate it correctly, so a failed check is reported as
    a warning rather than a hard rejection.

    Args:
        vin: 17-character VIN (case/space insensitive).

    Returns:
        ``{"vin","valid_format","check_digit_ok","wmi","vds","vis",
        "model_year_candidates","serial"}``.

    Raises:
        ValueError: If the VIN isn't 17 valid characters (I, O and Q are never
            used, to avoid confusion with 1 and 0).
    """
    v = re.sub(r"[\s-]", "", vin).upper()
    if not _VIN_RE.match(v):
        raise ValueError(
            f"not a valid 17-character VIN: {vin!r} (I, O, Q are never used)")
    total = sum(_VIN_VALUES[c] * w for c, w in zip(v, _VIN_WEIGHTS))
    expected = total % 11
    expected_char = "X" if expected == 10 else str(expected)
    return {"vin": v, "valid_format": True, "check_digit_ok": v[8] == expected_char,
            "check_digit_expected": expected_char, "check_digit_actual": v[8],
            "wmi": v[:3], "vds": v[3:9], "vis": v[9:],
            "model_year_candidates": _vin_year_candidates(v[9]), "serial": v[-6:]}


def decode_vin(vin: str, *, timeout: float = 20.0) -> dict:
    """Decode a VIN to a full specification via NHTSA vPIC.

    Args:
        vin: 17-character VIN.
        timeout: Request timeout in seconds.

    Returns:
        ``{"local", "decoded", "source"}`` — ``local`` is the offline check,
        ``decoded`` the non-empty fields NHTSA returned.

    Raises:
        ValueError: If the VIN is malformed.
    """
    local = validate_vin(vin)
    log(f"[*] decoding VIN {local['vin']} via NHTSA vPIC ...")
    data, r = fetch.get_json(
        "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/"
        f"{local['vin']}?format=json", timeout=timeout)
    results = (data or {}).get("Results") or []
    raw = results[0] if results else {}
    # vPIC returns ~140 keys, mostly empty; keep only what it actually knows.
    decoded = {k: v for k, v in raw.items()
               if v not in ("", None, "Not Applicable", "0") and k != "ErrorText"}
    return {"local": local, "decoded": decoded,
            "error_text": raw.get("ErrorText", ""),
            "source": "NHTSA vPIC" if decoded else "",
            "http_status": r.status}


def recalls(make: str, model: str, year: int, *, timeout: float = 20.0) -> dict:
    """Open NHTSA safety recalls for a make/model/year (US market)."""
    data, _ = fetch.get_json(
        "https://api.nhtsa.gov/recalls/recallsByVehicle?"
        f"make={make}&model={model}&modelYear={year}", timeout=timeout)
    items = (data or {}).get("results") or []
    return {"make": make, "model": model, "year": year, "count": len(items),
            "recalls": [{"campaign": i.get("NHTSACampaignNumber", ""),
                         "component": i.get("Component", ""),
                         "summary": i.get("Summary", "")[:300],
                         "remedy": i.get("Remedy", "")[:200]} for i in items[:20]]}


def _dvla(plate: str, timeout: float) -> dict:
    """DVLA Vehicle Enquiry Service ($DVLA_API_KEY). Vehicle data only, never
    owner data — that is not exposed by the API at all."""
    key = os.environ.get("DVLA_API_KEY", "")
    if not key:
        return {}
    import json as _json
    data, _ = fetch.get_json(
        "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles",
        headers={"x-api-key": key, "Content-Type": "application/json"},
        data=_json.dumps({"registrationNumber": re.sub(r"\s", "", plate).upper()}).encode(),
        timeout=timeout)
    if not isinstance(data, dict) or "registrationNumber" not in data:
        return {}
    return {k: data.get(k) for k in (
        "registrationNumber", "make", "colour", "fuelType", "engineCapacity",
        "yearOfManufacture", "monthOfFirstRegistration", "taxStatus",
        "taxDueDate", "motStatus", "motExpiryDate", "co2Emissions",
        "typeApproval", "wheelplan", "euroStatus") if data.get(k) is not None}


def _decode_gb(plate: str) -> dict:
    """UK plate: area code + age identifier -> region and registration half-year."""
    p = re.sub(r"[\s-]", "", plate).upper()
    m = re.match(r"^([A-Z]{2})(\d{2})([A-Z]{3})$", p)
    if not m:
        return {}
    area, age, _ = m.groups()
    n = int(age)
    # 01-49 -> March-August of 20NN; 51-99 -> September of 20(NN-50) to February.
    if 1 <= n <= 49:
        year, period = 2000 + n, "March–August"
    elif 51 <= n <= 99:
        year, period = 2000 + n - 50, f"September {2000 + n - 50}–February {2001 + n - 50}"
    else:
        return {"format": "current (2001-)", "area_code": area,
                "region": GB_MEMORY_TAGS.get(area[0], "unknown"),
                "note": "age identifier out of range"}
    return {"format": "current (2001-)", "area_code": area,
            "region": GB_MEMORY_TAGS.get(area[0], "unknown"),
            "first_registered_year": year, "first_registered_period": period}


def _decode_tr(plate: str) -> dict:
    """Turkish plate: leading two digits are the province of registration."""
    p = re.sub(r"[\s-]", "", plate).upper()
    m = re.match(r"^(\d{2})([A-Z]{1,3})(\d{2,5})$", p)
    if not m:
        return {}
    code, letters, digits = m.groups()
    if code not in TR_PROVINCES:
        return {}
    return {"format": "Turkey (province + letters + digits)", "province_code": code,
            "province": TR_PROVINCES[code], "letter_group": letters,
            "number_group": digits,
            "note": "Province is where the vehicle was registered, which is "
                    "usually but not always where the keeper lives."}


def _decode_de(plate: str) -> dict:
    """German plate: 1-3 letter district prefix, then 1-2 letters and digits.

    The split is ambiguous without the table — "HHAB123" parses as HHA|B|123 or
    HH|AB|123 — so candidate prefixes are tried longest-first and the first one
    that is a known district wins. Falls back to the longest structurally valid
    split when no prefix is recognized.
    """
    p = re.sub(r"[\s-]", "", plate).upper()
    if not re.match(r"^[A-ZÄÖÜ]{1,3}[A-Z]{1,2}\d{1,4}[EH]?$", p):
        return {}

    # If the writer separated the groups ("M AB 123"), that IS the answer —
    # guessing would turn München (M) into Mannheim (MA).
    parts = [x for x in re.split(r"[\s-]+", plate.strip().upper()) if x]
    if len(parts) >= 2 and re.fullmatch(r"[A-ZÄÖÜ]{1,3}", parts[0]):
        prefix = parts[0]
        return {"format": "Germany (district + letters + digits)",
                "district_code": prefix,
                "district": DE_DISTRICTS.get(
                    prefix, "unknown (structurally valid, but this prefix is not "
                            "in the built-in table of common districts)"),
                "letters": parts[1] if len(parts) > 2 else ""}

    fallback = None
    for n in (3, 2, 1):
        prefix, rest = p[:n], p[n:]
        if not re.match(r"^[A-Z]{1,2}\d{1,4}[EH]?$", rest):
            continue
        if prefix in DE_DISTRICTS:
            return {"format": "Germany (district + letters + digits)",
                    "district_code": prefix, "district": DE_DISTRICTS[prefix],
                    "letters": rest[:len(rest) - len(rest.lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))]}
        if fallback is None:
            fallback = prefix
    if fallback is None:
        return {}
    return {"format": "Germany (district + letters + digits)",
            "district_code": fallback,
            "district": "unknown (structurally valid, but this prefix is not in "
                        "the built-in table of common districts)"}


def _decode_us(plate: str) -> dict:
    """US plates carry no reliable public region/date encoding."""
    p = re.sub(r"[\s-]", "", plate).upper()
    if not re.match(r"^[A-Z0-9]{2,8}$", p):
        return {}
    return {"format": "United States (state-issued)",
            "note": "US plate formats are assigned per state and are not "
                    "self-describing — the issuing state cannot be derived from "
                    "the characters alone. You need the state from the plate's "
                    "design/text, then a DMV record request under a DPPA "
                    "permissible use for anything further."}


_PLATE_DECODERS = {"TR": _decode_tr, "GB": _decode_gb, "UK": _decode_gb,
                   "DE": _decode_de, "US": _decode_us}


def decode_plate(plate: str, *, country: str = "auto", timeout: float = 20.0) -> dict:
    """Decode a licence plate's region and, where encoded, registration date.

    Args:
        plate: The plate as written (spaces/dashes ignored).
        country: ISO code (TR/GB/DE/US) or ``auto`` to try every decoder and
            report each format the string is consistent with.
        timeout: Timeout for the optional DVLA lookup.

    Returns:
        ``{"plate","country","matches","dvla","owner_lookup","next_steps"}``.
        ``matches`` maps country code to what that country's scheme would make
        of the string — plural in auto mode, because plate formats overlap.

    Raises:
        ValueError: If the plate is empty or the country is unsupported.
    """
    p = plate.strip()
    if not p:
        raise ValueError("give a plate to decode")
    cc = country.upper()
    if cc not in ("AUTO", *_PLATE_DECODERS):
        raise ValueError(f"unsupported country {country!r}; "
                         f"use one of: {', '.join(sorted(set(_PLATE_DECODERS)))} or auto")

    decoders = _PLATE_DECODERS if cc == "AUTO" else {cc: _PLATE_DECODERS[cc]}
    matches = {code: out for code, fn in decoders.items() if (out := fn(p))}
    # GB and UK are the same decoder; don't report it twice.
    matches.pop("UK", None)

    dvla = {}
    if cc in ("GB", "UK") or (cc == "AUTO" and "GB" in matches):
        dvla = _dvla(p, timeout)

    steps = []
    if len(matches) > 1:
        steps.append("The string is valid under several national schemes — pass "
                     "--country to pick one. Plate formats are not globally unique.")
    if "TR" in matches:
        steps.append(f"Province {matches['TR']['province']} narrows any name search "
                     "enormously — pass it to osint.websearch --extra.")
    if "GB" in matches and matches["GB"].get("first_registered_year"):
        steps.append(f"First registered {matches['GB']['first_registered_period']} "
                     f"{matches['GB'].get('first_registered_year', '')} — that dates the "
                     "vehicle, not the current keeper.")
    if not dvla and ("GB" in matches):
        steps.append("Set $DVLA_API_KEY for the free DVLA Vehicle Enquiry API "
                     "(make, colour, engine, tax/MOT status — no owner data).")
    if not matches:
        steps.append("No built-in scheme matched. Decoding is supported for "
                     f"{', '.join(sorted(set(_PLATE_DECODERS) - {'UK'}))}.")

    return {
        "plate": p, "country": cc, "matches": matches, "dvla": dvla,
        "owner_lookup": {
            "available": False,
            "reason": "Vehicle-registration records tie a plate to a named person "
                      "and address, so they are protected personal data: DPPA "
                      "(18 U.S.C. 2721) in the US, GDPR in the EU/UK, KVKK in "
                      "Turkey. No lawful public API exposes them.",
            "lawful_routes": [
                "US: state DMV record request citing a DPPA permissible use "
                "(insurance, legal proceedings, licensed investigator, etc.)",
                "UK: DVLA form V888 with reasonable cause, or the free VES API "
                "for vehicle-only data",
                "EU/TR: request through the national vehicle authority, police "
                "report, or a court order",
                "Any: a lawyer's subpoena as part of actual proceedings",
            ],
            "note": "Sites advertising instant plate-to-owner lookup are selling "
                    "scraped or fabricated data; treat any result from them as "
                    "unverified and probably unlawful to rely on.",
        },
        "next_steps": steps,
    }


def run(
    *,
    vin: str = "",
    plate: str = "",
    country: str = "auto",
    make: str = "",
    model: str = "",
    year: int = 0,
    timeout: float = 20.0,
) -> dict:
    """Decode a VIN, a plate, or look up recalls.

    Args:
        vin: VIN to decode.
        plate: Licence plate to decode.
        country: Country hint for the plate.
        make, model, year: Recall lookup parameters.
        timeout: Per-request timeout.

    Returns:
        A dict with whichever of ``vin``/``plate``/``recalls`` was requested.

    Raises:
        ValueError: If no input was given, or an input is malformed.
    """
    if not (vin or plate or (make and model and year)):
        raise ValueError("give --vin, --plate, or --make/--model/--year")
    out: dict = {}
    if vin:
        out["vin"] = decode_vin(vin, timeout=timeout)
    if plate:
        out["plate"] = decode_plate(plate, country=country, timeout=timeout)
    if make and model and year:
        out["recalls"] = recalls(make, model, year, timeout=timeout)
    return out


def _compact_lines(res: dict) -> list[str]:
    lines: list[str] = []
    if v := res.get("vin"):
        loc = v["local"]
        lines.append(f"# VIN {loc['vin']}")
        ok = "ok" if loc["check_digit_ok"] else (
            f"MISMATCH (expected {loc['check_digit_expected']}, "
            f"got {loc['check_digit_actual']}) — typo, or a non-US-market vehicle")
        lines.append(f"  check digit  {ok}")
        lines.append(f"  wmi={loc['wmi']}  vds={loc['vds']}  vis={loc['vis']}  "
                     f"serial={loc['serial']}")
        if loc["model_year_candidates"]:
            years = " or ".join(str(y) for y in loc["model_year_candidates"])
            lines.append(f"  model year   {years}"
                         + ("  (code repeats every 30 years; the decode below "
                            "settles it)" if len(loc["model_year_candidates"]) > 1 else ""))
        if v["decoded"]:
            lines.append(f"## NHTSA vPIC ({len(v['decoded'])} fields)")
            for k, val in sorted(v["decoded"].items()):
                lines.append(f"  {k:<28} {val}")
        else:
            lines.append(f"## NHTSA vPIC returned nothing  {v.get('error_text', '')}")

    if p := res.get("plate"):
        lines.append(f"# PLATE {p['plate']}  (country={p['country']})")
        for code, m in p["matches"].items():
            lines.append(f"## {code}: {m.get('format', '')}")
            for k, val in m.items():
                if k != "format":
                    lines.append(f"  {k:<24} {val}")
        if not p["matches"]:
            lines.append("  no built-in scheme matched this string")
        if p["dvla"]:
            lines.append("## DVLA VEHICLE ENQUIRY (vehicle data only)")
            for k, val in p["dvla"].items():
                lines.append(f"  {k:<28} {val}")
        o = p["owner_lookup"]
        lines.append("## OWNER LOOKUP: NOT AVAILABLE")
        lines.append(f"  {o['reason']}")
        lines.append("  lawful routes:")
        lines += [f"    - {r}" for r in o["lawful_routes"]]
        lines.append(f"  {o['note']}")
        if p["next_steps"]:
            lines.append("## NEXT")
            lines += [f"  - {s}" for s in p["next_steps"]]

    if r := res.get("recalls"):
        lines.append(f"# RECALLS {r['make']} {r['model']} {r['year']}  ({r['count']})")
        for item in r["recalls"]:
            lines.append(f"  {item['campaign']}  {item['component']}")
            lines.append(f"    {item['summary']}")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.vehicle",
        description="Decode a VIN or a licence plate (region/date). No owner lookup — see --help.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('examples:\n'
                '  python -m osint.vehicle --vin 1HGCM82633A004352\n'
                '  python -m osint.vehicle --plate "34 ABC 123"\n'
                '  python -m osint.vehicle --plate "AB12 CDE" --country GB --json\n'
                '  python -m osint.vehicle --make Honda --model Accord --year 2003\n'
                '\nPlate-to-owner is not implemented: those records are protected\n'
                'by the DPPA (US), GDPR (EU/UK) and KVKK (TR). Run with --plate to\n'
                'see the lawful routes for obtaining them.\n'),
    )
    p.add_argument("--vin", default="", help="17-character VIN to decode.")
    p.add_argument("--plate", default="", help="Licence plate to decode.")
    p.add_argument("--country", default="auto",
                   help="Plate country: TR, GB, DE, US, or auto (default).")
    p.add_argument("--make", default="", help="Make, for --recalls.")
    p.add_argument("--model", default="", help="Model, for --recalls.")
    p.add_argument("--year", type=int, default=0, help="Model year, for --recalls.")
    p.add_argument("--recalls", action="store_true",
                   help="(implied when --make/--model/--year are given)")
    p.add_argument("--timeout", type=float, default=20.0, help="Timeout (default 20).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.vin or args.plate or (args.make and args.model and args.year)):
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(vin=args.vin, plate=args.plate, country=args.country,
                  make=args.make, model=args.model, year=args.year, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
