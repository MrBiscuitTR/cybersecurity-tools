import re

import pytest

from analyze import bughunt


def test_all_patterns_compile():
    for cls, sev, globs, pattern, why in bughunt.PATTERNS:
        re.compile(pattern)                    # Python-side sanity (rg is compatible)
        assert sev in ("high", "medium", "low")
        assert why


def test_run_classifies(monkeypatch, tmp_path):
    monkeypatch.setattr(bughunt, "_rg", lambda: "rg")
    # Simulate rg hits: sqli pattern matches app.py:1, others nothing.
    def fake_search(rg, repo, pattern, globs, per):
        if "SELECT" in pattern or "execute" in pattern:
            return [("app.py", 1, 'cur.execute("SELECT * FROM u WHERE id="+uid)')]
        return []
    monkeypatch.setattr(bughunt, "_search", fake_search)
    res = bughunt.run(str(tmp_path))
    assert res["total"] >= 1
    assert res["by_class"].get("sqli", 0) >= 1
    assert any(f["class"] == "sqli" for f in res["findings"])
    # notes file was written into the repo
    import os
    assert os.path.exists(res["notes_file"])


def test_run_no_rg(monkeypatch):
    monkeypatch.setattr(bughunt, "_rg", lambda: None)
    with pytest.raises(FileNotFoundError):
        bughunt.run("/some/path")


def test_write_notes(tmp_path):
    findings = [{"class": "xss", "severity": "high", "file": "a.js", "line": 3,
                 "snippet": "el.innerHTML = x", "why": "sink"}]
    p = bughunt._write_notes(str(tmp_path), "repo", findings,
                             {"high": 1, "medium": 0, "low": 0}, {"xss": 1})
    with open(p, encoding="utf-8") as fh:
        text = fh.read()
    assert "xss" in text and "a.js:3" in text and "SURVIVES compaction" in text


def test_main_no_args(capsys):
    assert bughunt.main([]) == 2
