import pytest

from osint import email as email_mod


@pytest.mark.parametrize("raw,expected", [
    ("Someone@Example.COM", "someone@example.com"),
    ("  a.b+tag@sub.example.co.uk ", "a.b+tag@sub.example.co.uk"),
    ("<x@y.com>", "x@y.com"),
])
def test_normalize(raw, expected):
    assert email_mod.normalize(raw) == expected


@pytest.mark.parametrize("bad", ["", "nope", "a@b", "@example.com", "a b@example.com"])
def test_normalize_rejects(bad):
    with pytest.raises(ValueError):
        email_mod.normalize(bad)


def test_hashes_match_gravatar_scheme():
    """Gravatar's documented example hash for this address."""
    h = email_mod.hashes("beau@dentedreality.com.au")
    assert h["md5"] == "205e460b479e2e5b48aec07710c08d50"
    assert len(h["sha256"]) == 64


def test_hashes_are_case_and_space_insensitive():
    assert email_mod.hashes(" A@B.com ") == email_mod.hashes("a@b.com")


def _run_with(monkeypatch, sources):
    """Run the tool with fetch.gather stubbed to return fixed source output."""
    monkeypatch.setattr(email_mod.fetch, "gather", lambda s, **k: (sources, {}))
    return email_mod.run("ada@example.com")


def test_identity_merges_gravatar_and_github(monkeypatch):
    res = _run_with(monkeypatch, {
        "gravatar": {"full_name": "Ada Lovelace", "display_name": "Ada",
                     "username": "adal", "location": "London", "about": "bio",
                     "accounts": [{"platform": "github", "url": "https://github.com/ada",
                                   "username": "ada", "verified": True}],
                     "urls": [{"title": "site", "value": "https://ada.test"}],
                     "photo": "p"},
        "github": {"users": [{"login": "ada", "url": "https://github.com/ada"}],
                   "commit_authors": [{"login": "ada2", "commit_name": "Ada L",
                                       "repos": ["x/y"]}]},
    })
    idt = res["identity"]
    assert "Ada Lovelace" in idt["names"]
    assert "Ada L" in idt["names"]          # name from git commit metadata
    assert set(idt["usernames"]) >= {"adal", "ada", "ada2"}
    assert idt["location"] == "London"
    assert any(a["verified"] for a in idt["linked_accounts"])


def test_breaches_merge_across_sources(monkeypatch):
    res = _run_with(monkeypatch, {
        "xposedornot": {"breaches": ["Adobe", "MySpace"], "clean": False},
        "leakcheck": {"found": 2, "sources": ["Adobe", "Canva"]},
        "hibp": {"clean": False, "count": 1,
                 "breaches": [{"name": "LinkedIn", "date": "2012", "data": []}]},
    })
    assert res["breaches"]["names"] == ["Adobe", "Canva", "LinkedIn", "MySpace"]


def test_classification_flags():
    res = email_mod.run("admin@mailinator.com", skip=("identity", "breaches",
                                                      "search", "dns"))
    c = res["classification"]
    assert c["role_account"] is True
    assert c["disposable"] is True


def test_plus_tag_extracted():
    res = email_mod.run("ada+github@example.com",
                        skip=("identity", "breaches", "search", "dns"))
    assert res["classification"]["plus_tag"] == "github"
    assert res["classification"]["base_local"] == "ada"


def test_next_steps_mention_recovered_name(monkeypatch):
    res = _run_with(monkeypatch, {"gravatar": {"full_name": "Ada Lovelace",
                                               "accounts": [], "urls": []}})
    assert any("Ada Lovelace" in s for s in res["next_steps"])


def test_hudsonrock_infection_surfaces(monkeypatch):
    res = _run_with(monkeypatch, {
        "hudsonrock": {"infected": True, "stealer_count": 1,
                       "computers": [{"date": "2023", "os": "Win", "ip": "1.2.3.4",
                                      "malware": "redline"}]}})
    assert any("infostealer" in s.lower() for s in res["next_steps"])
    assert any("INFOSTEALER" in l for l in email_mod._compact_lines(res))


def test_keyed_sources_return_empty_without_env(monkeypatch):
    for var in ("HIBP_API_KEY", "RAPIDAPI_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert email_mod._hibp("a@b.com", 1.0) == {}
    assert email_mod._breachdirectory("a@b.com", 1.0) == {}


def test_run_rejects_invalid_address():
    with pytest.raises(ValueError):
        email_mod.run("not-an-email")


def test_main_no_args_returns_2():
    assert email_mod.main([]) == 2
