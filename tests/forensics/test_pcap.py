import os

import pytest

from common import proc
from forensics import pcap

FIXTURE = os.path.join("data", "fixtures", "sample.pcap")


def _tshark():
    """Return a usable tshark path or None (so tests skip where it's absent)."""
    if proc.have("tshark"):
        return "tshark"
    win = r"C:\Program Files\Wireshark\tshark.exe"
    return win if os.path.exists(win) else None


needs_tshark = pytest.mark.skipif(_tshark() is None, reason="tshark not installed")


def test_main_no_args_returns_2(capsys):
    assert pcap.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_missing_file_returns_1(capsys):
    assert pcap.main(["does-not-exist.pcap"]) == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_sections_constant_covers_defaults():
    assert set(pcap.DEFAULT_SECTIONS) <= set(pcap.SECTIONS)


def test_decode_ssid():
    assert pcap._decode_ssid("696b65726972692d3567") == "ikeriri-5g"   # hex -> text
    assert pcap._decode_ssid("") == "<hidden>"
    assert pcap._decode_ssid("<MISSING>") == "<hidden>"
    assert pcap._decode_ssid("00") == "<hidden>"                        # all-null cloaked


def test_ip_key_sorts_numerically():
    ips = ["192.168.0.10", "192.168.0.2", "10.0.0.1", "notanip"]
    assert sorted(ips, key=pcap._ip_key)[:3] == ["10.0.0.1", "192.168.0.2", "192.168.0.10"]


def test_spn_from_sname():
    assert pcap._spn_from_sname("ldap,host.dom,dom") == "ldap/host.dom"
    assert pcap._spn_from_sname("krbtgt,REALM") == ""      # TGT, not roastable
    assert pcap._spn_from_sname("") == ""


def test_compact_renders_labeled_creds():
    res = {"file": "x.pcap", "sections": {"creds": [
        {"kind": "ftp", "user": "anonymous", "password": "a@b"},
        {"kind": "kerberoast-spn", "spn": "ldap/dc01", "note": "crack a TGS"},
    ]}}
    lines = pcap._compact_lines(res)
    assert any("[ftp] user=anonymous  password=a@b" in ln for ln in lines)
    assert any("[kerberoast-spn] spn=ldap/dc01  (crack a TGS)" in ln for ln in lines)


def test_compact_renders_loot_and_wifi():
    res = {"file": "x.pcap", "sections": {
        "creds": [{"kind": "ntlmv2", "value": "u::D:aa:bb:cc", "note": "hashcat -m 5600"}],
        "wifi": {"beacons": [{"ssid": "corp", "bssid": "aa:bb", "channel": "6",
                              "hidden": True, "revealed": True}],
                 "probe_requests": [], "wpa_handshakes": ["aa:bb"]},
    }}
    lines = pcap._compact_lines(res)
    assert any("hashcat -m 5600" in ln for ln in lines)
    assert any("SSID REVEALED" in ln for ln in lines)
    assert any("EAPOL handshake captured" in ln for ln in lines)


@needs_tshark
def test_digest_extracts_dns():
    res = pcap.run(FIXTURE, sections=["summary", "dns", "flows"], tshark=_tshark())
    assert res["sections"]["summary"]["packets"] == 2
    assert "udp" in res["sections"]["summary"]["protocols"]
    dns_rows = res["sections"]["dns"]
    assert any(d["query"] == "example.com" and d["answer"] == "93.184.216.34" for d in dns_rows)
    # sample.pcap is DNS-over-UDP -> at least one udp flow with a stream id.
    assert any(f["proto"] == "udp" for f in res["sections"]["flows"])


@needs_tshark
def test_filter_passthrough():
    res = pcap.filter_packets(FIXTURE, "dns", tshark=_tshark())
    assert res["matched"] == 2 and not res["truncated"]


@needs_tshark
def test_follow_udp_stream():
    res = pcap.follow(FIXTURE, "udp:0", tshark=_tshark())
    assert res["proto"] == "udp" and res["stream"] == 0
    assert "example.com" in res["content"] or res["content"]  # reassembled content present


@needs_tshark
def test_compact_lines_render():
    res = pcap.run(FIXTURE, sections=["summary", "dns"], tshark=_tshark())
    lines = pcap._compact_lines(res)
    assert lines[0].startswith("# pcap:")
    assert any("example.com" in ln for ln in lines)
