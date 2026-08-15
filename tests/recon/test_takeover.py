import pytest

from recon import takeover


def test_match_service():
    assert takeover._match_service("user.github.io")["service"] == "GitHub Pages"
    assert takeover._match_service("x.herokuapp.com")["service"] == "Heroku"
    assert takeover._match_service("nothing.example.net") is None


def test_no_cname_returns_none(monkeypatch):
    monkeypatch.setattr(takeover.dns, "resolve",
                        lambda name, rtype="A": {"cname": None, "status": 0, "answers": []})
    assert takeover.check_host("www.example.com") is None


def test_dangling_vulnerable_service_is_high(monkeypatch):
    # CNAME to GitHub Pages, and the target itself is NXDOMAIN -> dangling.
    def fake_resolve(name, rtype="A"):
        if rtype == "CNAME":
            return {"cname": "victim.github.io", "status": 0, "answers": []}
        return {"cname": None, "status": takeover.NXDOMAIN, "answers": []}  # A lookup
    monkeypatch.setattr(takeover.dns, "resolve", fake_resolve)

    f = takeover.check_host("blog.example.com")
    assert f["service"] == "GitHub Pages"
    assert f["dangling"] is True
    assert f["confidence"] == "high"


def test_live_service_is_low(monkeypatch):
    # CNAME to GitHub Pages but the target resolves fine -> informational only.
    def fake_resolve(name, rtype="A"):
        if rtype == "CNAME":
            return {"cname": "victim.github.io", "status": 0, "answers": []}
        return {"cname": None, "status": takeover.dns.NOERROR,
                "answers": [{"type": "A", "data": "185.199.108.153"}]}
    monkeypatch.setattr(takeover.dns, "resolve", fake_resolve)
    assert takeover.check_host("blog.example.com")["confidence"] == "low"


def test_main_no_input_returns_2(capsys):
    assert takeover.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_compact_lines_empty():
    res = {"checked": 5, "candidates": [], "summary": {"high": 0, "medium": 0, "low": 0}}
    lines = takeover._compact_lines(res)
    assert "no CNAMEs" in lines[1]
