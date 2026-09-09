import pytest

from osint import github


@pytest.mark.parametrize("email,name,is_bot", [
    ("vercel[bot]@users.noreply.github.com", "Vercel", True),
    ("49699333+dependabot[bot]@users.noreply.github.com", "dependabot", True),
    ("actions@github.com", "GitHub Actions", True),
    ("noreply@github.com", "", True),
    ("ece.gungor142@gmail.com", "Ece Güngör", False),
    ("77461507+mrbiscuittr@users.noreply.github.com", "Çağan Efe Çalıdağ", False),
])
def test_bot_address_detection(email, name, is_bot):
    assert github._is_bot_address(email, name) is is_bot


def test_name_key_folds_diacritics():
    assert github._name_key("Ece Güngör") == {"ece", "gungor"}
    assert github._name_key("Çağan Efe Çalıdağ") == {"cagan", "efe", "calidag"}


def _commit(email, name, linked_login=None):
    return {"author": ({"login": linked_login} if linked_login else None),
            "commit": {"author": {"email": email, "name": name},
                       "committer": {"email": email, "name": name}}}


def _fake_api(repos, commits):
    def get_json(url, **kw):
        if "/repos?" in url:
            return [{"full_name": r} for r in repos], None
        if "/commits" in url:
            return commits, None
        return None, None
    return get_json


def test_only_the_owners_commits_are_kept(monkeypatch):
    """A shared repo contains collaborators' addresses; reporting those as the
    subject's own is a false identification."""
    commits = [
        _commit("ece.gungor142@gmail.com", "Ece Güngör", linked_login="ecegungor"),
        _commit("alieren.tansu@gmail.com", "Ali Eren Tansu", linked_login="alieren"),
        _commit("someone@else.dev", "Someone Else"),
    ]
    monkeypatch.setattr(github.fetch, "get_json",
                        _fake_api(["ecegungor/water-recycle"], commits))
    monkeypatch.setattr(github.fetch, "gather",
                        lambda s, **k: ({n: f() for n, f in s.items()}, {}))
    res = github.commit_emails("ecegungor", owner_names=frozenset({"ece", "gungor"}))
    found = {e["email"] for e in res["emails"]}
    assert found == {"ece.gungor142@gmail.com"}


def test_unlinked_commit_is_kept_when_the_name_matches(monkeypatch):
    """An address configured on a laptop that was never added to the GitHub
    profile is exactly the one worth finding, so ?author= alone is too strict."""
    commits = [_commit("e.gungor@student.tue.nl", "Ece Güngör")]
    monkeypatch.setattr(github.fetch, "get_json",
                        _fake_api(["ecegungor/reroute"], commits))
    monkeypatch.setattr(github.fetch, "gather",
                        lambda s, **k: ({n: f() for n, f in s.items()}, {}))
    res = github.commit_emails("ecegungor", owner_names=frozenset({"ece", "gungor"}))
    assert [e["email"] for e in res["emails"]] == ["e.gungor@student.tue.nl"]
    assert "committed as" in res["emails"][0]["attribution"]


def test_noreply_is_flagged_and_yields_the_account_id(monkeypatch):
    commits = [_commit("77461507+mrbiscuittr@users.noreply.github.com",
                       "Çağan Efe Çalıdağ", linked_login="mrbiscuittr")]
    monkeypatch.setattr(github.fetch, "get_json", _fake_api(["mrbiscuittr/x"], commits))
    monkeypatch.setattr(github.fetch, "gather",
                        lambda s, **k: ({n: f() for n, f in s.items()}, {}))
    res = github.commit_emails("mrbiscuittr")
    assert res["emails"][0]["kind"] == "noreply"
    assert res["user_id"] == "77461507"


def test_real_addresses_sort_before_noreply(monkeypatch):
    commits = [_commit("1+u@users.noreply.github.com", "U", linked_login="u"),
               _commit("real@acme.dev", "U", linked_login="u")]
    monkeypatch.setattr(github.fetch, "get_json", _fake_api(["u/r"], commits))
    monkeypatch.setattr(github.fetch, "gather",
                        lambda s, **k: ({n: f() for n, f in s.items()}, {}))
    res = github.commit_emails("u")
    assert res["emails"][0]["kind"] == "real"


def test_run_rejects_bad_login():
    with pytest.raises(ValueError):
        github.run("not a login!")


def test_main_no_args_returns_2():
    assert github.main([]) == 2
