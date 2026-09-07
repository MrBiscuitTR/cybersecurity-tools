import pytest

from osint import fetch


def test_browser_headers_are_self_consistent():
    """A Chrome UA must carry client hints; a Firefox UA must not."""
    for browser in fetch._BROWSERS:
        h = fetch.browser_headers(browser=browser)
        assert h["User-Agent"] == browser["ua"]
        assert ("Sec-CH-UA" in h) == bool(browser["sec_ch_ua"])


def test_browser_headers_json_mode_is_xhr_shaped():
    h = fetch.browser_headers(accept="application/json")
    assert h["Sec-Fetch-Mode"] == "cors"
    assert h["X-Requested-With"] == "XMLHttpRequest"


def test_browser_headers_referer_changes_fetch_site():
    assert fetch.browser_headers()["Sec-Fetch-Site"] == "none"
    assert fetch.browser_headers(referer="https://x.test")["Sec-Fetch-Site"] == "cross-site"


def test_accept_encoding_only_advertises_decodable_formats():
    """Advertising br without a brotli decoder yields unreadable bytes."""
    assert "br" not in fetch.browser_headers()["Accept-Encoding"]


@pytest.mark.parametrize("status,body,blocked", [
    (200, b"<html>normal page</html>", False),
    (403, b"", True),
    (429, b"", True),
    (200, b"<title>Just a moment...</title>", True),
    (200, b"<h1>Client Challenge</h1>", True),
    (200, b"Enable JavaScript and cookies to continue", True),
])
def test_blocked_detection(status, body, blocked):
    assert fetch.Response("u", "u", status, body, None, 0.0).blocked is blocked


def test_text_uses_declared_charset():
    r = fetch.Response("u", "u", 200, "Ça".encode("latin-1"), None, 0.0,
                       headers={"content-type": "text/html; charset=latin-1"})
    assert r.text == "Ça"


def test_text_falls_back_to_meta_charset():
    body = b'<meta charset="latin-1"><p>' + "Ça".encode("latin-1") + b"</p>"
    assert "Ça" in fetch.Response("u", "u", 200, body, None, 0.0).text


def test_text_never_raises_on_bad_encoding():
    r = fetch.Response("u", "u", 200, b"\xff\xfe\x00bad",
                       None, 0.0, headers={"content-type": "text/html; charset=nonsense"})
    assert isinstance(r.text, str)


def test_json_raises_valueerror_on_garbage():
    with pytest.raises(ValueError):
        fetch.Response("u", "u", 200, b"not json", None, 0.0).json()


def test_gather_keeps_good_and_records_bad():
    def boom():
        raise RuntimeError("nope")

    got, down = fetch.gather({
        "good": lambda: ["a"],
        "empty": lambda: [],
        "bad": boom,
    })
    assert got == {"good": ["a"]}
    assert down["empty"] == "no results"
    assert "RuntimeError" in down["bad"]


def test_gather_empty_input():
    assert fetch.gather({}) == ({}, {})


def test_split_down_separates_empty_from_failed():
    empty, failed = fetch.split_down({"a": "no results", "b": "HTTP 500"})
    assert empty == ["a"] and failed == ["b"]


def test_get_first_returns_last_on_total_failure(monkeypatch):
    monkeypatch.setattr(fetch, "get",
                        lambda u, **k: fetch.Response(u, u, 500, b"", "err", 0.0))
    r = fetch.get_first(["https://a.test", "https://b.test"])
    assert r.status == 500 and r.url == "https://b.test"


def test_get_first_stops_at_first_success(monkeypatch):
    calls = []

    def fake_get(u, **k):
        calls.append(u)
        return fetch.Response(u, u, 200 if "b." in u else 500, b"ok", None, 0.0)

    monkeypatch.setattr(fetch, "get", fake_get)
    r = fetch.get_first(["https://a.test", "https://b.test", "https://c.test"])
    assert r.url == "https://b.test"
    assert calls == ["https://a.test", "https://b.test"]


def test_render_without_playwright_degrades_cleanly(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_playwright(name, *a, **k):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_playwright)
    out = fetch.render("https://example.test")
    assert out["rendered"] is False
    assert "playwright" in out["error"]
