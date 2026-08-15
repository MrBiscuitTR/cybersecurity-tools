from recon import playbook


def test_score_ranks_auth_and_keywords():
    admin_401 = {"host": "admin.example.com", "status": 401, "title": "", "server": "nginx",
                 "tech": ["nginx"]}
    boring = {"host": "cdn.example.com", "status": 200, "title": "img", "server": "cloudflare",
              "tech": []}
    s_admin, reasons = playbook._score(admin_401, "example.com")
    s_boring, _ = playbook._score(boring, "example.com")
    assert s_admin > s_boring
    assert any("auth-gated" in r for r in reasons)
    assert any("keyword" in r for r in reasons)


def test_run_orchestrates(monkeypatch):
    monkeypatch.setattr("recon.subdomains.run", lambda d, **k: {"subdomains": ["vault.example.com"]})
    monkeypatch.setattr("recon.http_probe.run", lambda hosts, **k: {"results": [
        {"host": "vault.example.com", "alive": True, "url": "https://vault.example.com/",
         "status": 200, "title": "Vaultwarden", "server": "nginx", "tech": []},
        {"host": "example.com", "alive": False}]})
    monkeypatch.setattr("web.js_recon.run", lambda url, **k: {"endpoints": ["/api"], "secrets": []})
    res = playbook.run("example.com")
    assert res["live_hosts"] == 1
    assert res["targets"][0]["host"] == "vault.example.com"
    assert any("vault" in " ".join(t["reasons"]) for t in res["targets"])


def test_main_no_args(capsys):
    assert playbook.main([]) == 2
