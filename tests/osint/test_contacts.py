import pytest

from osint import contacts


@pytest.mark.parametrize("raw,e164,country", [
    ("+90 532 123 45 67", "+905321234567", "Türkiye"),
    ("+44 20 7946 0958", "+442079460958", "United Kingdom"),
    ("+1 (415) 555-0132", "+14155550132", "NANP (US/Canada/Caribbean)"),
    ("0090 532 123 45 67", "+905321234567", "Türkiye"),
])
def test_normalize_phone_international(raw, e164, country):
    got = contacts.normalize_phone(raw)
    assert got and got["e164"] == e164 and got["country"] == country


def test_normalize_phone_national_needs_a_region():
    assert contacts.normalize_phone("0532 123 45 67") is None
    got = contacts.normalize_phone("0532 123 45 67", region="TR")
    assert got["e164"] == "+905321234567" and got["kind"] == "mobile"


@pytest.mark.parametrize("bad", [
    "2023-11-15",          # ISO date
    "14:22:01",            # timestamp
    "1.2.3",               # version string
    "123",                 # too short
    "1234567890123456789", # too long for E.164
    "0000000000",          # all one digit
    "+99 123 456 789",     # +99 is not an assigned calling code
])
def test_normalize_phone_rejects_non_numbers(bad):
    assert contacts.normalize_phone(bad, region="TR") is None


def test_turkish_mobile_detected():
    assert contacts.normalize_phone("+90 532 123 45 67")["kind"] == "mobile"
    assert contacts.normalize_phone("+90 212 555 44 33")["kind"] == ""


def test_phones_scores_by_context():
    text = ("Tel: +90 532 123 45 67. " + "filler words " * 12
            + "+442079460958 appears with no label nearby")
    out = contacts.phones(text)
    by = {p["e164"]: p for p in out}
    assert by["+905321234567"]["confidence"] == "high"       # explicit CC + "Tel:"
    assert by["+442079460958"]["confidence"] == "medium"     # explicit CC only


def test_phones_ignores_order_numbers_and_dates():
    text = "Order 20231115 shipped 2023-11-15 at 14:22:01, total 1500000"
    assert contacts.phones(text, region="TR") == []


def test_phones_dedupes_keeping_best_confidence():
    text = "+905321234567 ... phone: +90 532 123 45 67"
    out = contacts.phones(text)
    assert len(out) == 1 and out[0]["confidence"] == "high"


def test_addresses_from_jsonld():
    nodes = [{"@type": "Person", "address": {
        "@type": "PostalAddress", "streetAddress": "1 High St",
        "addressLocality": "London", "postalCode": "E1 6AN", "addressCountry": "GB"}}]
    out = contacts.addresses_from_jsonld(nodes)
    assert out[0]["confidence"] == "high"
    assert out[0]["locality"] == "London"
    assert "1 High St" in out[0]["formatted"]


def test_addresses_from_microformats():
    html = ('<span class="street-address">1 High St</span>'
            '<span class="locality">London</span>'
            '<span class="postal-code">E1 6AN</span>')
    out = contacts.addresses_from_microformats(html)
    assert out[0]["street"] == "1 High St" and out[0]["confidence"] == "high"


def test_addresses_from_text_pairs_nearest_postcode():
    """A London street must not be paired with a Turkish postcode 80 chars later."""
    text = ("Office: 42 Baker Street, London NW1 6XE. Also at "
            "Ataturk Cad. No: 15, Kadikoy 34710 Istanbul.")
    out = contacts.addresses_from_text(text, region="TR")
    formatted = [a["formatted"] for a in out]
    assert any("Baker Street" in f and "NW1 6XE" in f for f in formatted)
    assert not any("Baker Street" in f and "34710" in f for f in formatted)


def test_addresses_requires_street_and_postcode():
    assert contacts.addresses_from_text("just some text with 34710 in it") == []
    assert contacts.addresses_from_text("42 Baker Street with no postcode") == []


def test_ambiguous_postcode_shape_is_labelled_honestly():
    """A bare 5-digit code fits US/TR/DE/FR — naming one would invent precision."""
    out = contacts.addresses_from_text("15 Main Street, Springfield 62704")
    assert out and "ambiguous" in out[0]["country"]
    assert set(out[0]["country_candidates"]) >= {"US", "TR", "DE", "FR"}


def test_run_dedupes_contained_fragments():
    text = "Contact us. Suite 5, 42 Baker Street, London NW1 6XE"
    res = contacts.run(text=text)
    assert len(res["addresses"]) == 1


def test_run_prefers_structured_over_freetext():
    nodes = [{"@type": "PostalAddress", "streetAddress": "42 Baker Street",
              "addressLocality": "London", "postalCode": "NW1 6XE"}]
    res = contacts.run(text="42 Baker Street, London NW1 6XE", jsonld=nodes)
    assert res["addresses"][0]["confidence"] == "high"


def test_calling_codes_are_longest_prefix_matched():
    # +90 is Türkiye; +9 is not a code, and +905 must not shadow it.
    assert contacts.normalize_phone("+905321234567")["country_code"] == "+90"
    # +1 (NANP) is a single digit and must still resolve.
    assert contacts.normalize_phone("+14155550132")["country_code"] == "+1"


def test_main_no_args_returns_2():
    assert contacts.main([]) == 2
