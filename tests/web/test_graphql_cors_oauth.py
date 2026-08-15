import pytest

from web import cors, graphql, oauth


# --- graphql ---------------------------------------------------------------
def test_graphql_findings(monkeypatch):
    schema = {"queryType": {"name": "Query", "fields": [{"name": "me"}]},
              "mutationType": {"name": "Mutation",
                               "fields": [{"name": "deleteUser", "args": []},
                                          {"name": "login", "args": []}]},
              "subscriptionType": None,
              "types": [{"name": "User", "kind": "OBJECT",
                         "fields": [{"name": "password"}, {"name": "email"}]}]}
    monkeypatch.setattr(graphql, "_post",
                        lambda url, q, t: {"status": 200, "json": {"data": {"__schema": schema}}})
    monkeypatch.setattr(graphql, "_get_probe", lambda url, t: True)
    res = graphql.run("http://x/graphql")
    assert res["introspection"] is True
    assert "deleteUser" in res["dangerous_mutations"]
    assert any("User.password" in f for f in res["sensitive_fields"])
    notes = " ".join(f["note"] for f in res["findings"])
    assert "introspection" in notes and "CSRF" in notes


def test_graphql_disabled(monkeypatch):
    monkeypatch.setattr(graphql, "_post", lambda url, q, t: {"status": 400, "json": None})
    res = graphql.run("http://x/graphql")
    assert res["introspection"] is False


# --- cors ------------------------------------------------------------------
def test_cors_reflection_with_creds(monkeypatch):
    def fake_probe(url, origin, timeout):
        return {"origin": origin, "acao": origin, "acac": True}  # reflect everything + creds
    monkeypatch.setattr(cors, "_probe", fake_probe)
    res = cors.run("https://api.example.com/me")
    assert res["vulnerable"] is True
    assert any(f["level"] == "high" for f in res["findings"])


def test_cors_safe(monkeypatch):
    monkeypatch.setattr(cors, "_probe",
                        lambda u, o, t: {"origin": o, "acao": "*", "acac": False})
    res = cors.run("https://x/")
    assert res["vulnerable"] is False


# --- oauth -----------------------------------------------------------------
def test_oauth_flags_implicit_and_pkce(monkeypatch):
    doc = {"issuer": "https://i", "authorization_endpoint": "https://i/auth",
           "token_endpoint": "https://i/token",
           "response_types_supported": ["code", "token", "id_token"],
           "grant_types_supported": ["authorization_code"],
           "scopes_supported": ["openid"], "token_endpoint_auth_methods_supported": ["none"]}

    class R:
        ok = True
        def json(self):
            return doc
    monkeypatch.setattr(oauth.http, "get", lambda *a, **k: R())
    res = oauth.run("https://i")
    notes = " ".join(f["note"] for f in res["findings"])
    assert "implicit flow" in notes and "PKCE" in notes and "none" in notes


def test_discovery_url():
    assert oauth._discovery_url("https://i").endswith("/.well-known/openid-configuration")
    assert oauth._discovery_url("https://i/.well-known/openid-configuration").count("well-known") == 1


@pytest.mark.parametrize("mod", [graphql, cors, oauth])
def test_main_no_args(mod, capsys):
    assert mod.main([]) == 2
