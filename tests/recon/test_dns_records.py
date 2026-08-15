import pytest

from recon import dns_records


def test_main_no_args_returns_2(capsys):
    assert dns_records.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_run_collects_records_and_axfr(monkeypatch):
    def fake_resolve(name, rtype="A"):
        table = {
            "A": [{"type": "A", "data": "1.2.3.4"}],
            "NS": [{"type": "NS", "data": "ns1.example.com"}],
            "MX": [{"type": "MX", "data": "10 mail.example.com"}],
        }
        return {"answers": table.get(rtype, []), "status": 0}
    monkeypatch.setattr(dns_records.dns, "resolve", fake_resolve)
    monkeypatch.setattr(dns_records.dns, "a_records", lambda n: ["10.0.0.53"])
    monkeypatch.setattr(dns_records.dns, "axfr",
                        lambda zone, ip, **k: {"ok": True, "error": None,
                                               "records": [{"type": "A", "data": "1.2.3.4"}]})
    res = dns_records.run("example.com")
    assert res["records"]["A"] == ["1.2.3.4"]
    assert res["nameservers"] == ["ns1.example.com"]
    assert res["axfr"][0]["ok"] and res["axfr"][0]["record_count"] == 1


def test_compact_flags_open_axfr():
    res = {
        "domain": "example.com",
        "records": {"A": ["1.2.3.4"]},
        "nameservers": ["ns1.example.com"],
        "axfr": [{"nameserver": "ns1.example.com", "address": "10.0.0.53", "ok": True,
                  "record_count": 1, "records": [{"type": "A", "data": "1.2.3.4"}],
                  "error": None}],
    }
    lines = dns_records._compact_lines(res)
    assert any("VULNERABLE" in ln for ln in lines)
    assert any("LEAKED" in ln for ln in lines)


def test_compact_refused_is_good():
    res = {
        "domain": "example.com",
        "records": {"A": ["1.2.3.4"]},
        "nameservers": ["ns1.example.com"],
        "axfr": [{"nameserver": "ns1.example.com", "address": "10.0.0.53", "ok": False,
                  "record_count": 0, "records": [], "error": "refused/empty"}],
    }
    lines = dns_records._compact_lines(res)
    assert any("refused (good)" in ln for ln in lines)


@pytest.mark.network
def test_run_live_no_axfr():
    res = dns_records.run("example.com", axfr=False)
    assert res["domain"] == "example.com"
    assert "A" in res["records"] or "AAAA" in res["records"]
