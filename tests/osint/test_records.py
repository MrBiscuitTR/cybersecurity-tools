import pytest

from osint import records


def test_wd_value_literal_time():
    claim = {"mainsnak": {"datavalue": {"value": {"time": "+1815-12-10T00:00:00Z"}}}}
    assert records._wd_value(claim) == ("1815-12-10", "")


def test_wd_value_entity_reference():
    claim = {"mainsnak": {"datavalue": {"value": {"id": "Q84"}}}}
    assert records._wd_value(claim) == ("", "Q84")


def test_wd_value_plain_string():
    claim = {"mainsnak": {"datavalue": {"value": "adalovelace"}}}
    assert records._wd_value(claim) == ("adalovelace", "")


def test_wd_value_empty_claim():
    assert records._wd_value({}) == ("", "")


def test_wikidata_expands_claims_and_labels(monkeypatch):
    def fake_get_json(url, **kw):
        if "wbsearchentities" in url:
            return {"search": [{"id": "Q7259", "label": "Ada Lovelace",
                                "description": "mathematician"}]}, None
        if "EntityData" in url:
            return {"entities": {"Q7259": {
                "labels": {"en": {"value": "Ada Lovelace"}},
                "descriptions": {"en": {"value": "mathematician"}},
                "claims": {
                    "P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}],
                    "P569": [{"mainsnak": {"datavalue": {
                        "value": {"time": "+1815-12-10T00:00:00Z"}}}}],
                    "P69": [{"mainsnak": {"datavalue": {"value": {"id": "Q99"}}}}],
                    "P2037": [{"mainsnak": {"datavalue": {"value": "adalovelace"}}}],
                }}}}, None
        if "wbgetentities" in url:
            return {"entities": {"Q99": {"labels": {"en": {"value": "Home Tutoring"}}}}}, None
        return None, None

    monkeypatch.setattr(records.fetch, "get_json", fake_get_json)
    out = records._wikidata("Ada Lovelace", "person", 5.0)
    assert out["is_human"] is True
    assert out["fields"]["birth_date"] == ["1815-12-10"]
    assert out["fields"]["educated_at"] == ["Home Tutoring"]   # QID resolved to a label
    assert out["fields"]["github"] == ["adalovelace"]


def test_wikidata_no_hits(monkeypatch):
    monkeypatch.setattr(records.fetch, "get_json", lambda *a, **k: ({"search": []}, None))
    assert records._wikidata("zzz", "person", 5.0) == {}


def test_sec_edgar_builds_filing_urls(monkeypatch):
    monkeypatch.setattr(records.fetch, "get_json", lambda *a, **k: ({"hits": {
        "total": {"value": 2},
        "hits": [{"_id": "0001045810-22-000163:x.htm",
                  "_source": {"display_names": ["NVIDIA CORP"], "file_type": "EX-99.1",
                              "file_date": "2022-11-16", "ciks": ["0001045810"]}}]}}, None))
    out = records._sec_edgar("Ada", 5.0)
    assert out["total"] == 2
    assert out["filings"][0]["url"].startswith(
        "https://www.sec.gov/Archives/edgar/data/1045810/")


def test_gleif_flattens_addresses(monkeypatch):
    monkeypatch.setattr(records.fetch, "get_json", lambda *a, **k: ({"data": [{
        "id": "LEI123", "attributes": {"entity": {
            "legalName": {"name": "Acme Ltd"}, "status": "ACTIVE",
            "jurisdiction": "GB",
            "legalAddress": {"addressLines": ["1 High St"], "city": "London",
                             "postalCode": "E1", "country": "GB"}}}}]}, None))
    out = records._gleif("Acme", 5.0)
    assert out["entities"][0]["name"] == "Acme Ltd"
    assert "London" in out["entities"][0]["address"]


def test_keyed_sources_skip_without_env(monkeypatch):
    for var in ("OPENCORPORATES_API_KEY", "COMPANIES_HOUSE_KEY", "OPENSANCTIONS_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert records._opencorporates("x", 1.0) == {}
    assert records._companies_house("x", 1.0) == {}
    assert records._opensanctions("x", 1.0) == {}


def test_run_shape_and_next_steps(monkeypatch):
    monkeypatch.setattr(records.fetch, "gather", lambda s, **k: ({
        "wikidata": {"label": "Ada Lovelace", "description": "mathematician",
                     "is_human": True, "url": "https://wikidata.org/wiki/Q7259",
                     "fields": {"birth_date": ["1815-12-10"],
                                "educated_at": ["Home Tutoring"],
                                "github": ["adalovelace"]},
                     "candidates": [{"id": "Q1", "label": "a", "description": "b"}]},
    }, {"gleif": "no results", "opensanctions": "HTTP 401"}))
    res = records.run("Ada Lovelace")
    assert res["person"]["birth_date"] == ["1815-12-10"]
    assert res["person"]["handles"]["github"] == ["adalovelace"]
    assert any("1815-12-10" in s for s in res["next_steps"])
    lines = records._compact_lines(res)
    assert any("no match in: gleif" in l for l in lines)
    assert any("unavailable: opensanctions" in l for l in lines)


def test_run_rejects_bad_input():
    with pytest.raises(ValueError):
        records.run("")
    with pytest.raises(ValueError):
        records.run("Ada", kind="nonsense")


def test_main_no_args_returns_2():
    assert records.main([]) == 2


@pytest.mark.network
def test_wikidata_live():
    out = records._wikidata("Ada Lovelace", "person", 20.0)
    assert out["fields"]["birth_date"] == ["1815-12-10"]
