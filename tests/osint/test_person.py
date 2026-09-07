import pytest

from osint import person


def _score(**kw):
    base = {"target_name": "Ada Lovelace", "handles": {"ada"}, "emails": set(),
            "location": "", "employer": "", "declared_urls": set()}
    acct = kw.pop("acct", {})
    base.update(kw)
    return person._score_account(acct, **base)


def test_self_declared_link_is_confirmed():
    conf, _, why = _score(acct={"url": "https://x.test/ada", "self_declared": True,
                                "declared_by": "rel=me"})
    assert conf == "CONFIRMED"
    assert any("self-declared" in w for w in why)


def test_url_in_declared_set_is_confirmed():
    conf, _, _ = _score(acct={"url": "https://x.test/ada"},
                        declared_urls={"https://x.test/ada"})
    assert conf == "CONFIRMED"


def test_handle_only_match_is_medium_not_high():
    """A bare handle match must not masquerade as a confident identification."""
    conf, _, _ = _score(acct={"url": "https://x.test/ada", "handle": "ada"})
    assert conf == "MEDIUM"


def test_unknown_account_is_low_with_warning():
    conf, _, why = _score(acct={"url": "https://x.test/zzz", "handle": "zzz"})
    assert conf == "LOW"
    assert any("different person" in w for w in why)


def test_exact_name_match_raises_confidence():
    conf, _, _ = _score(acct={"url": "https://x.test/ada", "handle": "ada",
                              "profile_name": "Ada Lovelace"})
    assert conf == "HIGH"


def test_conflicting_name_is_penalized():
    _, score_ok, _ = _score(acct={"url": "https://a.test/x", "handle": "ada",
                                  "profile_name": "Ada Lovelace"})
    _, score_bad, why = _score(acct={"url": "https://b.test/x", "handle": "ada",
                                     "profile_name": "Bob Smith"})
    assert score_bad < score_ok
    assert any("does NOT match" in w for w in why)


def test_email_in_bio_is_strong_evidence():
    conf, _, why = _score(acct={"url": "https://x.test/a", "handle": "zzz",
                                "bio": "reach me at ada@example.com"},
                          emails={"ada@example.com"})
    assert conf in ("MEDIUM", "HIGH")
    assert any("ada@example.com" in w for w in why)


def test_location_and_employer_add_evidence():
    _, score, why = _score(acct={"url": "https://x.test/a", "handle": "ada",
                                 "bio": "Engineer at Acme in London"},
                           location="London", employer="Acme")
    assert any("location" in w for w in why)
    assert any("employer" in w for w in why)


def test_run_requires_a_seed():
    with pytest.raises(ValueError):
        person.run()


def test_run_rejects_unknown_stage():
    with pytest.raises(ValueError):
        person.run(handles=["ada"], stages=("nonsense",))


def test_seed_stage_expands_name_without_network():
    res = person.run(name="Cagan Efe Calidag", stages=("seed",))
    assert res["stages_run"] == ["seed"]
    assert "cagancalidag" in res["seed"]["handles"]


def test_correlate_only_produces_empty_but_valid_result():
    res = person.run(handles=["ada"], stages=("correlate",))
    assert res["accounts"] == []
    assert res["identity"]["names"] == []
    assert res["next_steps"]


def test_username_hits_become_scored_accounts(monkeypatch):
    """The username stage's hits must flow into correlation, not be dropped."""
    import osint.username as username_mod
    monkeypatch.setattr(username_mod, "run", lambda handles, **kw: {
        "usernames": list(handles), "invalid": [], "checked_sites": 2,
        "control_username": "", "unreliable_sites": [],
        "found": [{"site": "github", "category": "dev", "username": "ada",
                   "url": "https://github.com/ada", "state": "found",
                   "http": 200, "note": ""}],
        "unreliable": [], "unknown": [], "manual": [],
        "per_username": {"ada": {"found": ["github"], "unknown": 0, "absent": 1}},
        "next_steps": []})
    res = person.run(handles=["ada"], stages=("username", "correlate"))
    assert [a["url"] for a in res["accounts"]] == ["https://github.com/ada"]
    assert res["accounts"][0]["confidence"] == "MEDIUM"


def test_compact_lines_render():
    res = person.run(handles=["ada"], stages=("correlate",))
    lines = person._compact_lines(res)
    assert any("person:" in l for l in lines)
    assert any("NEXT" in l for l in lines)


def test_main_no_args_returns_2():
    assert person.main([]) == 2


def test_stages_constant_is_ordered():
    assert person.STAGES[0] == "seed"
    assert person.STAGES[-1] == "correlate"
