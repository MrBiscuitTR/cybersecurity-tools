"""Offline tests for nuclei, dirfuzz, ssrf, smuggle wrappers."""
import pytest

from recon import nuclei
from web import dirfuzz, smuggle, ssrf


# --- nuclei ----------------------------------------------------------------
def test_nuclei_parse_and_rank(monkeypatch):
    from common import proc
    jsonl = "\n".join([
        '{"template-id":"cve-x","info":{"name":"RCE","severity":"critical"},"matched-at":"https://t/a"}',
        '{"template-id":"exp-y","info":{"name":"Panel","severity":"low"},"matched-at":"https://t/b"}',
        '{"template-id":"cve-x","info":{"name":"RCE","severity":"critical"},"matched-at":"https://t/a"}',
    ])
    monkeypatch.setattr(nuclei, "_nuclei", lambda: "nuclei")
    monkeypatch.setattr(nuclei.proc, "run", lambda *a, **k: proc.Ran(["nuclei"], 0, jsonl, "", True))
    res = nuclei.run("https://t")
    assert res["total"] == 2                        # deduped
    assert res["findings"][0]["severity"] == "critical"   # ranked first
    assert res["by_severity"]["critical"] == 1


def test_nuclei_no_binary(monkeypatch):
    monkeypatch.setattr(nuclei, "_nuclei", lambda: None)
    with pytest.raises(FileNotFoundError):
        nuclei.run("https://t")


# --- dirfuzz ---------------------------------------------------------------
def test_dirfuzz_soft404_filter(monkeypatch):
    # Every unknown path returns 200/len 1000 (soft-404); only /admin differs.
    def fake_fetch(url, timeout):
        if url.endswith("/admin"):
            return 200, 4242, ""
        return 200, 1000, ""
    monkeypatch.setattr(dirfuzz, "_fetch", fake_fetch)
    res = dirfuzz.run("https://t", wordlist="")
    paths = [h["path"] for h in res["hits"]]
    assert "admin" in paths
    assert all(h["length"] != 1000 for h in res["hits"])   # soft-404s filtered


def test_dirfuzz_candidates():
    c = dirfuzz._candidates(["admin", "index.php"], ["php", "bak"])
    assert "admin" in c and "admin.php" in c and "admin.bak" in c
    assert "index.php" in c and "index.php.php" not in c    # already has extension


# --- ssrf ------------------------------------------------------------------
def test_ssrf_inject():
    assert ssrf._inject("http://t/f?url=FUZZ", "", "P") == "http://t/f?url=P"
    assert "x=P" in ssrf._inject("http://t/f?x=1", "x", "P")


def test_ssrf_detects_metadata(monkeypatch):
    class R:
        def __init__(self, body, status=200):
            self.body = body.encode(); self.text = body; self.status = status
    def fake_get(url, **k):
        if "etc/passwd" in url:
            return R("root:x:0:0:root:/root:/bin/bash")
        return R("normal page here")
    monkeypatch.setattr(ssrf.httpc, "get", fake_get)
    res = ssrf.run("http://t/f?url=FUZZ")
    assert res["vulnerable"]
    assert any("file" in f["payload"] and f["level"] == "high" for f in res["findings"])


# --- smuggle ---------------------------------------------------------------
def test_smuggle_payloads_shape():
    p = smuggle._payloads("t", "/")
    assert b"Content-Length: 0" in p["baseline"]
    assert b"Transfer-Encoding: chunked" in p["CL.TE"]


def test_smuggle_detects_delay(monkeypatch):
    # baseline fast, CL.TE hangs (= timeout), others fast -> flag CL.TE.
    def fake_raw(host, port, ssl_, payload, timeout):
        return 11.0 if b"1\r\nA\r\nX" in payload else 0.2
    monkeypatch.setattr(smuggle, "_raw", fake_raw)
    res = smuggle.run("https://t/", rounds=1)
    assert res["vulnerable"]
    assert res["findings"][0]["type"] == "CL.TE"


@pytest.mark.parametrize("mod", [nuclei, dirfuzz, ssrf, smuggle])
def test_main_no_args(mod, capsys):
    assert mod.main([]) == 2
