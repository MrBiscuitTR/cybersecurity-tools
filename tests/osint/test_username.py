import pytest

from osint import fetch, username


@pytest.mark.parametrize("raw,expected", [
    ("torvalds", "torvalds"),
    ("@torvalds", "torvalds"),
    ("  Torvalds ", "Torvalds"),
    ("https://github.com/torvalds", "torvalds"),
    ("https://github.com/torvalds/", "torvalds"),
])
def test_normalize(raw, expected):
    assert username.normalize(raw) == expected


@pytest.mark.parametrize("bad", ["", "  ", "has space", "a" * 60, "-leading"])
def test_normalize_rejects(bad):
    with pytest.raises(ValueError):
        username.normalize(bad)


def _resp(status, body=b""):
    return fetch.Response("u", "u", status, body, None, 0.0)


def test_check_site_status_mode(monkeypatch):
    site = username.Site("demo", "https://demo.test/{u}", "dev")
    monkeypatch.setattr(username.fetch, "get", lambda *a, **k: _resp(200))
    assert username.check_site(site, "x")["state"] == "found"
    monkeypatch.setattr(username.fetch, "get", lambda *a, **k: _resp(404))
    assert username.check_site(site, "x")["state"] == "absent"
    monkeypatch.setattr(username.fetch, "get", lambda *a, **k: _resp(500))
    assert username.check_site(site, "x")["state"] == "unknown"


def test_check_site_blocked_200_is_not_found(monkeypatch):
    """A 200 that is really a bot wall must not be reported as an account."""
    site = username.Site("demo", "https://demo.test/{u}", "dev")
    monkeypatch.setattr(username.fetch, "get",
                        lambda *a, **k: _resp(200, b"<title>Just a moment...</title>"))
    assert username.check_site(site, "x")["state"] == "unknown"


def test_check_site_text_mode_exists_marker(monkeypatch):
    site = username.Site("tg", "https://t.me/{u}", "social", mode="text",
                         exists_text="tgme_page_title")
    monkeypatch.setattr(username.fetch, "get",
                        lambda *a, **k: _resp(200, b"...tgme_page_title..."))
    assert username.check_site(site, "x")["state"] == "found"
    monkeypatch.setattr(username.fetch, "get", lambda *a, **k: _resp(200, b"nope"))
    assert username.check_site(site, "x")["state"] == "absent"


def test_check_site_text_mode_absent_marker(monkeypatch):
    site = username.Site("steam", "https://s.test/{u}", "gaming", mode="text",
                         absent_text="could not be found")
    monkeypatch.setattr(username.fetch, "get",
                        lambda *a, **k: _resp(200, b"profile could not be found"))
    assert username.check_site(site, "x")["state"] == "absent"


def test_manual_sites_are_never_probed(monkeypatch):
    site = username.Site("ig", "https://ig.test/{u}", "social", mode="manual")

    def boom(*a, **k):
        raise AssertionError("manual sites must not issue a request")

    monkeypatch.setattr(username.fetch, "get", boom)
    res = username.check_site(site, "x")
    assert res["state"] == "manual" and res["url"] == "https://ig.test/x"


def test_control_probe_quarantines_yes_to_everything_sites(monkeypatch):
    """The core guarantee: a site that 'finds' a random handle is demoted."""
    monkeypatch.setattr(username, "SITES", [
        username.Site("liar", "https://liar.test/{u}", "dev"),
        username.Site("honest", "https://honest.test/{u}", "dev"),
    ])

    def fake_get(url, **kw):
        return _resp(200) if "liar" in url else (
            _resp(200) if url.endswith("/real") else _resp(404))

    monkeypatch.setattr(username.fetch, "get", fake_get)
    res = username.run("real")
    assert res["unreliable_sites"] == ["liar"]
    assert [h["site"] for h in res["found"]] == ["honest"]
    assert any(u["site"] == "liar" for u in res["unreliable"])


def test_multiple_handles_are_swept_together(monkeypatch):
    monkeypatch.setattr(username, "SITES",
                        [username.Site("s", "https://s.test/{u}", "dev")])
    monkeypatch.setattr(username.fetch, "get",
                        lambda url, **k: _resp(200 if url.endswith("/a") else 404))
    res = username.run(["a", "b"], control=False)
    assert res["usernames"] == ["a", "b"]
    assert res["per_username"]["a"]["found"] == ["s"]
    assert res["per_username"]["b"]["found"] == []


def test_run_dedupes_and_reports_invalid(monkeypatch):
    monkeypatch.setattr(username, "SITES",
                        [username.Site("s", "https://s.test/{u}", "dev")])
    monkeypatch.setattr(username.fetch, "get", lambda *a, **k: _resp(404))
    res = username.run(["a", "a", "bad name"], control=False)
    assert res["usernames"] == ["a"]
    assert res["invalid"]


def test_run_rejects_all_invalid():
    with pytest.raises(ValueError):
        username.run(["bad name!!"])


def test_site_table_is_coherent():
    for s in username.SITES:
        assert "{u}" in s.url or s.mode == "manual"
        assert s.mode in ("status", "text", "meta", "manual")
        if s.mode == "text":
            assert s.exists_text or s.absent_text
        assert s.category in username.CATEGORIES


def test_big_social_platforms_are_actually_checked():
    """Instagram/X/Facebook/TikTok serve public profile metadata — reporting
    them as unverifiable 'manual' hides accounts that are plainly findable."""
    modes = {s.name: s.mode for s in username.SITES}
    for site in ("instagram", "x/twitter", "facebook", "threads", "tiktok",
                 "twitch", "medium", "pinterest", "snapchat"):
        assert modes[site] != "manual", f"{site} should be checked, not manual"


def _meta_page(title, desc=""):
    return (f'<meta property="og:title" content="{title}">'
            f'<meta property="og:description" content="{desc}">').encode()


def test_meta_mode_extracts_name_and_stats(monkeypatch):
    site = username.Site("instagram", "https://ig.test/{u}/", "social", mode="meta")
    monkeypatch.setattr(username.fetch, "get", lambda *a, **k: _resp(
        200, _meta_page("Çağan Efe Çalıdağ (@cagancalidag)",
                        "307 Followers, 377 Following, 0 Posts - See Instagram")))
    res = username.check_site(site, "cagancalidag")
    assert res["state"] == "found"
    assert res["profile_name"] == "Çağan Efe Çalıdağ"
    assert res["stats"]["follower"] == "307"
    assert res["stats"]["following"] == "377"


def test_meta_mode_absent_when_no_og_title(monkeypatch):
    site = username.Site("instagram", "https://ig.test/{u}/", "social", mode="meta")
    monkeypatch.setattr(username.fetch, "get",
                        lambda *a, **k: _resp(200, b"<html>generic page</html>"))
    assert username.check_site(site, "nobody")["state"] == "absent"


def test_meta_mode_absent_title_patterns(monkeypatch):
    site = username.Site("threads", "https://th.test/@{u}", "social", mode="meta",
                         absent_title=("Log in",))
    monkeypatch.setattr(username.fetch, "get",
                        lambda *a, **k: _resp(200, _meta_page("Threads • Log in")))
    assert username.check_site(site, "nobody")["state"] == "absent"


def test_text_mode_substitutes_the_handle(monkeypatch):
    """TikTok's marker is handle-specific: '"uniqueId":"<handle>"'."""
    site = username.Site("tiktok", "https://tt.test/@{u}", "social", mode="text",
                         exists_text='"uniqueId":"{u}"')
    monkeypatch.setattr(username.fetch, "get",
                        lambda *a, **k: _resp(200, b'x "uniqueId":"realuser" y'))
    assert username.check_site(site, "realuser")["state"] == "found"
    assert username.check_site(site, "otheruser")["state"] == "absent"


@pytest.mark.parametrize("title,desc,name,stat_key", [
    ("jack (@jack) on X", "", "jack", None),
    ("Ninja - Twitch", "Just want to make people happy", "Ninja", None),
    ("Dan – Medium", "", "Dan", None),
    ("Mark Zuckerberg (@zuck) • Threads, Say more",
     "5.7M Followers • 158 Threads", "Mark Zuckerberg", "follower"),
])
def test_parse_profile_meta(title, desc, name, stat_key):
    got_name, stats = username._parse_profile_meta(title, desc)
    assert got_name == name
    if stat_key:
        assert stat_key in stats


def test_main_no_args_returns_2():
    assert username.main([]) == 2


def test_main_rejects_bad_category():
    assert username.main(["x", "--category", "nonsense"]) == 1
