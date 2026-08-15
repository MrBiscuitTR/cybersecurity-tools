import struct

import pytest

from common import dns


def _build_a_response(name: str, ip: str) -> bytes:
    """Craft a minimal wireformat DNS response: one A answer, using a compression
    pointer for the answer name (exercises the pointer path in _read_name)."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    question = qname + struct.pack(">HH", 1, 1)              # A, IN
    answer = struct.pack(">H", 0xC00C)                       # pointer to offset 12 (qname)
    answer += struct.pack(">HHIH", 1, 1, 300, 4)             # A, IN, ttl, rdlen=4
    answer += bytes(int(o) for o in ip.split("."))
    return header + question + answer


def test_build_query_shape():
    q = dns._build_query("example.com", "A")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
    assert flags == 0x0100 and qd == 1  # recursion desired, one question
    assert q.endswith(struct.pack(">HH", 1, 1))  # QTYPE=A, QCLASS=IN
    assert b"\x07example\x03com\x00" in q        # length-prefixed labels


def test_parse_response_with_compression_pointer():
    msg = _build_a_response("example.com", "93.184.216.34")
    rcode, answers = dns._parse_response(msg)
    assert rcode == dns.NOERROR
    assert answers == [{"type": "A", "data": "93.184.216.34"}]


def test_resolve_uses_wireformat(monkeypatch):
    body = _build_a_response("example.com", "1.2.3.4")

    class FakeResp:
        ok = True
        def __init__(self):
            self.body = body

    monkeypatch.setattr(dns.http, "get", lambda *a, **k: FakeResp())
    r = dns.resolve("example.com", "A")
    assert r["status"] == 0
    assert {"type": "A", "data": "1.2.3.4"} in r["answers"]
    assert r["provider"] == "quad9"  # first resolver that "answered"


def test_resolve_all_providers_fail(monkeypatch):
    class Bad:
        ok = False
        body = b""
    monkeypatch.setattr(dns.http, "get", lambda *a, **k: Bad())
    r = dns.resolve("x.example.com")
    assert r["status"] == -1 and r["answers"] == []


def test_privacy_order_no_google():
    names = [n for n, _ in dns.RESOLVERS]
    assert names[0] == "quad9"
    assert not any("google" in url.lower() for _, url in dns.RESOLVERS)


def test_parse_rdata_srv():
    name = b"\x03svc\x07example\x03com\x00"
    rdata = struct.pack(">HHH", 10, 20, 443) + name
    assert dns._parse_rdata(rdata, 33, 0, len(rdata)) == "10 20 443 svc.example.com"


def test_parse_rdata_caa():
    tag = b"issue"
    rdata = bytes([0, len(tag)]) + tag + b"letsencrypt.org"
    assert dns._parse_rdata(rdata, 257, 0, len(rdata)) == "0 issue letsencrypt.org"


def test_parse_rdata_ptr():
    name = b"\x04host\x07example\x03com\x00"
    assert dns._parse_rdata(name, 12, 0, len(name)) == "host.example.com"


class _FakeSock:
    """Minimal socket stand-in that replays framed AXFR bytes once."""
    def __init__(self, framed: bytes):
        self._data = framed
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def settimeout(self, _):
        pass
    def sendall(self, _):
        pass
    def recv(self, _n):
        data, self._data = self._data, b""
        return data


def _framed_response_with_a(zone: str, ip: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x0001, 0x8180, 1, 1, 0, 0)
    qname = b"".join(bytes([len(l)]) + l.encode() for l in zone.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 252, 1)          # AXFR
    answer = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 1, 1, 300, 4)
    answer += bytes(int(o) for o in ip.split("."))
    msg = header + question + answer
    return struct.pack(">H", len(msg)) + msg               # TCP length prefix


def test_axfr_success(monkeypatch):
    framed = _framed_response_with_a("zonetransfer.me", "1.2.3.4")
    monkeypatch.setattr(dns.socket, "create_connection",
                        lambda *a, **k: _FakeSock(framed))
    r = dns.axfr("zonetransfer.me", "10.0.0.53")
    assert r["ok"] is True
    assert {"type": "A", "data": "1.2.3.4"} in r["records"]


def test_axfr_refused(monkeypatch):
    def boom(*a, **k):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(dns.socket, "create_connection", boom)
    r = dns.axfr("example.com", "10.0.0.53")
    assert r["ok"] is False and "refused" in r["error"].lower()


@pytest.mark.network
def test_resolve_live():
    r = dns.resolve("example.com", "A")
    assert r["status"] == 0 and any(a["type"] == "A" for a in r["answers"])
    assert r["provider"] in {"quad9", "mullvad", "cloudflare"}
