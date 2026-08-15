import pytest

from recon import secrets_scan


def test_scan_finds_secrets(tmp_path):
    (tmp_path / "config.js").write_text(
        'const k="AKIAIOSFODNN7EXAMPLE";\napi_key: "supersecret12345"\n', encoding="utf-8")
    (tmp_path / "gh.env").write_text(
        "TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    res = secrets_scan.run(str(tmp_path))
    types = res["by_type"]
    assert types.get("aws-access-key") == 1
    assert types.get("github-token") == 1
    assert any(f["file"] == "config.js" and f["line"] == 1 for f in res["findings"])


def test_scan_skips_binary_and_dirs(tmp_path):
    (tmp_path / "logo.png").write_bytes(b"AKIAIOSFODNN7EXAMPLE")   # skipped by extension
    skipdir = tmp_path / ".git"
    skipdir.mkdir()
    (skipdir / "x.txt").write_text("ghp_1234567890abcdefghijklmnopqrstuvwxyz", encoding="utf-8")
    res = secrets_scan.run(str(tmp_path))
    assert res["count"] == 0


def test_redact():
    assert secrets_scan._redact("short") == "sho…"
    r = secrets_scan._redact("AKIAIOSFODNN7EXAMPLE")
    assert r.startswith("AKIAIO") and r.endswith("MPLE") and "…" in r


def test_missing_path_returns_1(capsys):
    assert secrets_scan.main(["/no/such/path/xyz"]) == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_main_no_args_returns_2(capsys):
    assert secrets_scan.main([]) == 2
