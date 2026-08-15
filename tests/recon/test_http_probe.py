import pytest

from recon import http_probe


def test_decode_title_entities_and_charset():
    body = b"<html><head><title>Foo &amp; Bar\n  Baz</title></head>"
    assert http_probe._decode_title(body, "text/html") == "Foo & Bar Baz"


def test_decode_title_missing():
    assert http_probe._decode_title(b"<html>no title</html>", "") == ""


def test_guess_tech_from_headers_and_body():
    tech = http_probe._guess_tech({"server": "nginx", "x-powered-by": "PHP/8.1"},
                                  b"<html>wp-content</html>")
    assert "nginx" in tech and "php" in tech and "wordpress" in tech


def test_probe_host_follows_redirect(monkeypatch):
    seq = iter([
        {"status": 301, "headers": {"location": "https://example.com/home"}, "body": b"", "final": ""},
        {"status": 200, "headers": {"server": "nginx", "content-type": "text/html"},
         "body": b"<title>Home</title>", "final": ""},
    ])
    monkeypatch.setattr(http_probe, "_fetch", lambda url, timeout: next(seq))
    r = http_probe.probe_host("example.com")
    assert r["alive"] and r["status"] == 200
    assert r["title"] == "Home" and r["server"] == "nginx"
    assert r["redirects"] == ["https://example.com/home"]


def test_probe_host_dead(monkeypatch):
    monkeypatch.setattr(http_probe, "_fetch", lambda url, timeout: None)
    r = http_probe.probe_host("nope.invalid")
    assert r["alive"] is False and r["status"] is None


def test_run_counts_live(monkeypatch):
    def fake_probe(host, **k):
        return {"host": host, "alive": host != "dead.example",
                "status": 200 if host != "dead.example" else None,
                "title": "", "server": "", "content_length": "", "content_type": "",
                "redirects": [], "final_url": "", "url": "https://%s/" % host, "tech": []}
    monkeypatch.setattr(http_probe, "probe_host", fake_probe)
    res = http_probe.run(["a.example", "dead.example", "b.example"])
    assert res["count"] == 3 and res["live"] == 2


def test_compact_lines_hides_dead_by_default():
    res = {"count": 2, "live": 1, "results": [
        {"host": "a", "alive": True, "url": "https://a/", "status": 200, "title": "A",
         "server": "nginx", "content_length": "10", "redirects": [], "final_url": "https://a/",
         "tech": ["nginx"]},
        {"host": "b", "alive": False, "status": None, "title": "", "server": "",
         "content_length": "", "redirects": [], "final_url": "", "url": "", "tech": []},
    ]}
    live_only = http_probe._compact_lines(res, show_dead=False)
    assert any("https://a/" in ln for ln in live_only)
    assert not any("[dead]" in ln for ln in live_only)
    assert any("[dead]" in ln for ln in http_probe._compact_lines(res, show_dead=True))


def test_main_no_args_returns_2(capsys):
    assert http_probe.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


@pytest.mark.network
def test_run_live_smoke():
    res = http_probe.run(["example.com"])
    assert res["live"] == 1
    assert res["results"][0]["status"] == 200
