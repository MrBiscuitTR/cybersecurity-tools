import pytest

from web import js_recon


def test_extract_secrets_detects_common_keys():
    bodies = {"app.js": (
        'const aws="AKIAIOSFODNN7EXAMPLE";'
        'var g="AIzaSyA1234567890abcdefghijklmnopqrstuv";'
        'const gh="ghp_1234567890abcdefghijklmnopqrstuvwxyz";'
        'let stripe="sk_live_0123456789abcdefghijkl";'
        'api_key: "supersecretvalue123"'
    )}
    secrets = js_recon._extract_secrets(bodies)
    types = {s["type"] for s in secrets}
    assert "aws-access-key" in types
    assert "google-api-key" in types
    assert "github-token" in types
    assert "stripe-secret" in types
    assert "generic-secret" in types
    assert all(s["source"] == "app.js" for s in secrets)


def test_extract_secrets_private_key():
    bodies = {"x": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"}
    assert any(s["type"] == "private-key" for s in js_recon._extract_secrets(bodies))


def test_extract_endpoints_filters_assets():
    bodies = {"x": (
        'fetch("/api/v1/users");'
        'axios.get("/admin/settings");'
        'img.src="/static/logo.png";'
        'load("https://api.example.com/v2/data");'
    )}
    eps = js_recon._extract_endpoints("https://example.com", bodies)
    assert "/api/v1/users" in eps
    assert "/admin/settings" in eps
    assert "https://api.example.com/v2/data" in eps
    assert not any(e.endswith("logo.png") for e in eps)   # static asset dropped


def test_extract_params_interesting_only():
    bodies = {"x": '{"username":"a","auth_token":"b","color":"red","is_admin":true}'}
    params = js_recon._extract_params(bodies)
    assert "auth_token" in params and "is_admin" in params
    assert "color" not in params


def test_collect_scripts_parses_html(monkeypatch):
    html = ('<script src="/static/app.js"></script>'
            '<script>var inline_secret="ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";</script>')
    monkeypatch.setattr(js_recon, "_fetch_text", lambda url, timeout: "// external js")
    scripts, bodies = js_recon._collect_scripts("https://x.com/", html, 5, 4)
    assert "https://x.com/static/app.js" in scripts
    assert any(k.startswith("inline#") for k in bodies)


def test_main_no_args_returns_2(capsys):
    assert js_recon.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


@pytest.mark.network
def test_run_live_smoke():
    res = js_recon.run("https://example.com")
    assert res["target"].startswith("http")
    assert "stats" in res
