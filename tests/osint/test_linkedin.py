import pytest

from osint import fetch, linkedin

PROFILE_HTML = """
<html><head>
<meta property="og:description" content="Chair of the Gates Foundation · Experience: Gates Foundation · Education: Harvard University · Location: Seattle">
<script type="application/ld+json">
{"@context":"http://schema.org","@graph":[
 {"@type":"Person","name":"Bill Gates","disambiguatingDescription":"Creator",
  "jobTitle":["Co-chair"],
  "address":{"@type":"PostalAddress","addressLocality":"Seattle","addressCountry":"US"},
  "worksFor":[{"@type":"Organization","name":"Gates Foundation",
               "url":"https://www.linkedin.com/company/gates-foundation",
               "member":{"@type":"OrganizationRole","startDate":2000}}],
  "alumniOf":[{"@type":"EducationalOrganization","name":"Harvard University",
               "member":{"@type":"OrganizationRole","startDate":1973,"endDate":1975}}]}]}
</script></head><body></body></html>
"""


@pytest.mark.parametrize("raw,vanity", [
    ("williamhgates", "williamhgates"),
    ("/in/williamhgates", "williamhgates"),
    ("linkedin.com/in/williamhgates", "williamhgates"),
    ("https://www.linkedin.com/in/williamhgates/", "williamhgates"),
    ("https://tr.linkedin.com/in/williamhgates?trk=x", "williamhgates"),
])
def test_normalize(raw, vanity):
    v, url = linkedin.normalize(raw)
    assert v == vanity
    assert url == f"https://www.linkedin.com/in/{vanity}"


@pytest.mark.parametrize("bad", ["", "https://linkedin.com/company/acme", "ab"])
def test_normalize_rejects(bad):
    with pytest.raises(ValueError):
        linkedin.normalize(bad)


def _stub(monkeypatch, status, body):
    monkeypatch.setattr(linkedin.fetch, "get",
                        lambda *a, **k: fetch.Response("u", "u", status,
                                                       body.encode(), None, 0.0))


def test_lookup_parses_career_and_education(monkeypatch):
    _stub(monkeypatch, 200, PROFILE_HTML)
    res = linkedin.lookup("williamhgates")
    assert res["found"] is True
    assert res["identity"]["name"] == "Bill Gates"
    assert res["identity"]["locality"] == "Seattle"
    assert res["experience"][0]["name"] == "Gates Foundation"
    assert res["experience"][0]["start"] == "2000"
    assert res["education"][0]["end"] == "1975"


def test_lookup_reads_og_summary(monkeypatch):
    _stub(monkeypatch, 200, PROFILE_HTML)
    res = linkedin.lookup("williamhgates")
    assert res["og_summary"]["education"].startswith("Harvard")


def test_lookup_999_is_not_reported_as_absent(monkeypatch):
    """LinkedIn's rate-limit code must never be read as 'no such profile'."""
    _stub(monkeypatch, 999, "")
    res = linkedin.lookup("someone")
    assert res["found"] is False
    assert res["http_status"] == 999
    assert any("999" in s and "not mean" in s.lower() for s in res["next_steps"])


def test_lookup_authwall_detected(monkeypatch):
    _stub(monkeypatch, 200, "<html>Join LinkedIn to see this profile authwall</html>")
    res = linkedin.lookup("someone")
    assert res["authwall"] is True and res["found"] is False


def test_discover_collects_profiles(monkeypatch):
    def fake_search(q, **kw):
        return {"results": [
            {"url": "https://www.linkedin.com/in/adalovelace", "title": "Ada - Eng",
             "snippet": "Experience: Acme", "agreement": 3},
            {"url": "https://example.com/other", "title": "Other", "snippet": "",
             "agreement": 1},
        ], "engines_used": ["bing"], "engines_down": {}}

    import osint.websearch as ws
    monkeypatch.setattr(ws, "search", fake_search)
    res = linkedin.discover("Ada Lovelace")
    assert res["profiles"][0]["vanity"] == "adalovelace"
    assert res["profiles"][0]["agreement"] == 3
    assert res["other_hits"]


def test_discover_requires_a_name():
    with pytest.raises(ValueError):
        linkedin.discover("  ")


def test_discover_no_results_advises(monkeypatch):
    import osint.websearch as ws
    monkeypatch.setattr(ws, "search", lambda q, **kw: {
        "results": [], "engines_used": [], "engines_down": {}})
    res = linkedin.discover("Nobody Here")
    assert not res["profiles"]
    assert any("private profile" in s or "spelling" in s for s in res["next_steps"])


def test_main_no_args_returns_2():
    assert linkedin.main([]) == 2


@pytest.mark.network
def test_lookup_live_public_profile():
    res = linkedin.lookup("williamhgates")
    assert res["http_status"] in (200, 999)
