import pytest

from recon import favicon


def test_murmur3_known_vectors():
    # Standard mmh3 x86_32 test vectors (signed).
    assert favicon.murmur3_x86_32(b"") == 0
    assert favicon.murmur3_x86_32(b"hello") == 613153351


def test_favicon_hash_is_stable():
    data = b"\x89PNG\r\n\x1a\n" + b"icon-bytes" * 10
    h1 = favicon.favicon_hash(data)
    h2 = favicon.favicon_hash(data)
    assert h1 == h2 and isinstance(h1, int)


def test_run_builds_pivots(monkeypatch):
    class R:
        ok = True
        body = b"\x00\x00\x01\x00" + b"favicondata" * 20
        error = None
        status = 200
    monkeypatch.setattr(favicon.http, "get", lambda *a, **k: R())
    res = favicon.run("https://example.com/favicon.ico")
    assert res["hash"] == favicon.favicon_hash(R.body)
    assert str(res["hash"]) in res["pivots"]["shodan"]
    assert res["pivots"]["fofa"].startswith("icon_hash=")


def test_main_no_args_returns_2(capsys):
    assert favicon.main([]) == 2
