import pytest

from recon import asn


@pytest.mark.parametrize("target,kind,norm", [
    ("AS13335", "asn", "AS13335"),
    ("13335", "asn", "AS13335"),
    ("1.1.1.1", "ip", "1.1.1.1"),
    ("example.com", "domain", "example.com"),
])
def test_classify(target, kind, norm):
    assert asn._classify(target) == (kind, norm)


def test_run_for_ip(monkeypatch):
    def fake_ripe(endpoint, resource):
        if endpoint == "network-info":
            return {"asns": ["13335"], "prefix": "1.1.1.0/24"}
        if endpoint == "as-overview":
            return {"holder": "CLOUDFLARENET"}
        if endpoint == "announced-prefixes":
            return {"prefixes": [{"prefix": "1.1.1.0/24"}, {"prefix": "2606:4700::/32"}]}
        return {}
    monkeypatch.setattr(asn, "_ripe", fake_ripe)
    res = asn.run("1.1.1.1")
    assert res["queried_ip"] == "1.1.1.1"
    a = res["asns"][0]
    assert a["asn"] == "AS13335" and a["holder"] == "CLOUDFLARENET"
    assert "1.1.1.0/24" in a["prefixes_v4"] and "2606:4700::/32" in a["prefixes_v6"]


def test_run_domain_unresolvable(monkeypatch):
    monkeypatch.setattr(asn.dns, "a_records", lambda n: [])
    with pytest.raises(ValueError):
        asn.run("nope.invalid")


def test_main_no_args_returns_2(capsys):
    assert asn.main([]) == 2


@pytest.mark.network
def test_run_live_asn():
    res = asn.run("AS13335", max_prefixes=3)
    assert res["asns"][0]["asn"] == "AS13335"
    assert res["asns"][0]["prefix_count"] > 0
