"""DNS lookups over HTTPS (DoH), stdlib-only, using privacy-respecting resolvers.

Speaks RFC 8484 wireformat (application/dns-message) rather than the JSON DoH API,
because that's what the privacy-first resolvers support. Provider order, most to
least preferred: Quad9 -> Mullvad -> Cloudflare. Google is intentionally NOT used.

Why wireformat instead of the simpler ?name=&type= JSON API: only Cloudflare and
Google expose that JSON API; Quad9 and Mullvad do not. Wireformat is a bit more
code (a small DNS packet builder/parser below) but keeps us on the resolvers we
actually want, with zero third-party dependencies.

APIs (all free, no-auth):
    https://dns.quad9.net/dns-query        (Quad9,    RFC 8484)
    https://dns.mullvad.net/dns-query      (Mullvad,  RFC 8484)
    https://cloudflare-dns.com/dns-query   (Cloudflare, RFC 8484)

Read-only. Resolves names; never modifies anything.
"""

from __future__ import annotations

import base64
import os
import socket
import struct

from common import http

# Ordered by privacy preference. First to answer wins.
RESOLVERS: list[tuple[str, str]] = [
    ("quad9", "https://dns.quad9.net/dns-query"),
    ("mullvad", "https://dns.mullvad.net/dns-query"),
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
]

_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "SRV": 33, "CAA": 257, "AXFR": 252}
_NUM_TYPE = {v: k for k, v in _TYPE_NUM.items()}

# DNS RCODEs (low nibble of the response flags).
NOERROR, FORMERR, SERVFAIL, NXDOMAIN = 0, 1, 2, 3


# --- wireformat: build a query ---------------------------------------------

def _build_query(name: str, rtype: str) -> bytes:
    """Build a minimal DNS query packet (one question, recursion desired)."""
    qid = int.from_bytes(os.urandom(2), "big")
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1, QDCOUNT=1
    # Punycode-encode the whole name once (handles IDNs), then length-prefix labels.
    ascii_name = name.rstrip(".").encode("idna").decode() if not name.isascii() else name.rstrip(".")
    qname = b""
    for label in ascii_name.split("."):
        raw = label.encode("ascii")
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    question = qname + struct.pack(">HH", _TYPE_NUM.get(rtype, 1), 1)  # QCLASS=IN
    return header + question


# --- wireformat: parse a response ------------------------------------------

def _read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Read a (possibly compressed) domain name starting at ``off``.

    Returns (name, offset_after_name_in_the_stream). Compression pointers are
    followed for the name value, but the returned offset advances past the
    pointer in the original stream, per DNS rules.
    """
    labels: list[str] = []
    jumped = False
    original_off = off
    while True:
        if off >= len(msg):
            break
        length = msg[off]
        if length & 0xC0 == 0xC0:  # compression pointer (top 2 bits set)
            pointer = ((length & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                original_off = off + 2
            off = pointer
            jumped = True
            continue
        if length == 0:  # root label -> end of name
            off += 1
            break
        labels.append(msg[off + 1: off + 1 + length].decode("latin-1"))
        off += 1 + length
    name = ".".join(labels)
    return name, (original_off if jumped else off)


def _parse_rdata(msg: bytes, rtype: int, rdoff: int, rdlen: int) -> str:
    """Turn an answer's RDATA into a readable string for the record type."""
    rd = msg[rdoff: rdoff + rdlen]
    if rtype == 1 and rdlen == 4:                       # A
        return ".".join(str(b) for b in rd)
    if rtype == 28 and rdlen == 16:                     # AAAA
        parts = [f"{(rd[i] << 8) | rd[i + 1]:x}" for i in range(0, 16, 2)]
        return ":".join(parts)
    if rtype in (5, 2, 12):                             # CNAME, NS, PTR
        return _read_name(msg, rdoff)[0]
    if rtype == 15:                                     # MX: pref + exchange
        pref = (rd[0] << 8) | rd[1]
        return f"{pref} {_read_name(msg, rdoff + 2)[0]}"
    if rtype == 33:                                     # SRV: prio weight port target
        prio, weight, port = struct.unpack(">HHH", rd[:6])
        return f"{prio} {weight} {port} {_read_name(msg, rdoff + 6)[0]}"
    if rtype == 257:                                    # CAA: flags, tag, value
        flags = rd[0]
        taglen = rd[1]
        tag = rd[2:2 + taglen].decode("latin-1")
        value = rd[2 + taglen:].decode("latin-1")
        return f"{flags} {tag} {value}"
    if rtype == 16:                                     # TXT: one or more strings
        out, i = [], 0
        while i < rdlen:
            slen = rd[i]
            out.append(rd[i + 1: i + 1 + slen].decode("latin-1"))
            i += 1 + slen
        return "".join(out)
    if rtype == 6:                                      # SOA: mname rname ...
        mname, o = _read_name(msg, rdoff)
        rname, _ = _read_name(msg, o)
        return f"{mname} {rname}"
    return rd.hex()


def _parse_response(msg: bytes) -> tuple[int, list[dict]]:
    """Parse a wireformat response into (rcode, [{"type","data"}, ...])."""
    if len(msg) < 12:
        return -1, []
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):                       # skip questions
        _, off = _read_name(msg, off)
        off += 4                              # QTYPE + QCLASS
    answers: list[dict] = []
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off: off + 10])
        off += 10
        answers.append({"type": _NUM_TYPE.get(rtype, str(rtype)),
                        "data": _parse_rdata(msg, rtype, off, rdlen)})
        off += rdlen
    return rcode, answers


# --- public API -------------------------------------------------------------

def resolve(name: str, rtype: str = "A") -> dict:
    """Resolve ``name``/``rtype`` via DoH, trying Quad9, then Mullvad, then Cloudflare.

    Args:
        name: Hostname to look up.
        rtype: Record type, e.g. "A", "CNAME", "TXT", "MX", "NS", "AAAA".

    Returns:
        {
          "name": str, "type": str,
          "status": int,          # DNS RCODE: 0=NOERROR, 3=NXDOMAIN, -1=lookup failed
          "answers": [{"type": str, "data": str}, ...],
          "cname": str | None,    # first CNAME target in the answer, if any
          "provider": str | None, # which resolver answered
        }
    """
    query = _build_query(name, rtype)
    dns_param = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
    for provider, base in RESOLVERS:
        r = http.get(
            f"{base}?dns={dns_param}",
            headers={"Accept": "application/dns-message"},
            timeout=8,
            retries=0,  # 3 independent resolvers already provide redundancy
        )
        if not r.ok or not r.body:
            continue
        rcode, answers = _parse_response(r.body)
        if rcode == -1:
            continue
        for a in answers:
            a["data"] = a["data"].rstrip(".")
        cname = next((a["data"] for a in answers if a["type"] == "CNAME"), None)
        return {"name": name, "type": rtype, "status": rcode,
                "answers": answers, "cname": cname, "provider": provider}
    return {"name": name, "type": rtype, "status": -1,
            "answers": [], "cname": None, "provider": None}


def axfr(zone: str, nameserver: str, *, timeout: float = 8.0) -> dict:
    """Attempt a DNS zone transfer (AXFR) from ``nameserver`` for ``zone``.

    AXFR uses TCP straight to the authoritative nameserver (DoH resolvers won't
    proxy it), so this opens a direct socket to ``nameserver`` on port 53. A
    successful transfer means the server is misconfigured to hand its whole zone
    to anyone — a classic finding.

    Args:
        zone: The domain/zone to request (e.g. "example.com").
        nameserver: IP or hostname of the NS to ask.
        timeout: Socket timeout in seconds.

    Returns:
        {"nameserver", "zone", "ok": bool, "records": [{"type","data"}...],
         "error": str | None}. ok=True only when records were actually returned.
    """
    query = _build_query(zone, "AXFR")
    records: list[dict] = []
    try:
        with socket.create_connection((nameserver, 53), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack(">H", len(query)) + query)  # TCP: 2-byte length prefix
            buf = b""
            # Read length-prefixed messages until the stream closes or we've read enough.
            while True:
                chunk = sock.recv(65535)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 2:
                    mlen = struct.unpack(">H", buf[:2])[0]
                    if len(buf) < 2 + mlen:
                        break
                    msg = buf[2:2 + mlen]
                    buf = buf[2 + mlen:]
                    _rcode, answers = _parse_response(msg)
                    for a in answers:
                        a["data"] = a["data"].rstrip(".")
                    records.extend(answers)
                if len(records) > 100000:  # safety bound
                    break
    except (OSError, socket.timeout) as exc:
        return {"nameserver": nameserver, "zone": zone, "ok": False,
                "records": [], "error": f"{type(exc).__name__}: {exc}"}
    return {"nameserver": nameserver, "zone": zone, "ok": bool(records),
            "records": records, "error": None if records else "refused/empty"}


def a_records(name: str) -> list[str]:
    """Convenience: list of A-record IPs for ``name`` (empty if none/NXDOMAIN)."""
    return [a["data"] for a in resolve(name, "A")["answers"] if a["type"] == "A"]


def cname_target(name: str) -> str | None:
    """Convenience: the CNAME target for ``name``, or None."""
    return resolve(name, "CNAME")["cname"]
