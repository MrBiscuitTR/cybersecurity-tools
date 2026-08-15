"""Read a pcap/pcapng capture and turn it into intelligence an LLM can act on.

Wraps ``tshark`` (Wireshark). A raw packet dump of a real capture is far too
large and too low-level to reason over; this tool distills a capture into compact
sections, and — crucially — lets you DRILL DOWN: follow a specific TCP/UDP stream,
or run any Wireshark display filter and get the matching packets back. So it works
as both a fast overview and a scalpel, which is what a pentest needs.

THREE MODES
  1. digest (default)      -> compact multi-section overview of the whole capture
  2. --stream N            -> follow (reassemble) one TCP stream's full content
     --stream udp:N        -> same for a UDP stream (QUIC, DNS, VoIP, ...)
  3. --filter "<dfilter>"  -> run any Wireshark display filter, return matches
     --list-streams        -> index of TCP streams (id, endpoints, bytes) to follow

DIGEST SECTIONS (auto-skip when empty, so absence is itself information)
  summary   packets, duration, link type, and which protocols are present
  proto     protocol hierarchy (encapsulation tree with per-layer bytes)
  flows     top TCP/UDP flows with STREAM IDs + SNI/host, so you can follow one
  tls       TLS/QUIC SNI (server names contacted) + negotiated versions
  dns       DNS queries -> answers
  http      HTTP requests (method/host/uri) and responses (status)
  services  service/host discovery: mDNS, LLMNR, NBNS, SSDP
  arp       ARP who-has/is-at (L2 host map; works on monitor-mode captures too)
  wifi      802.11 beacons (SSID/BSSID/channel) and probe requests — monitor mode
  creds     heuristic cleartext credentials: HTTP basic/POST, FTP, Telnet, SMTP/IMAP/POP

CAPABILITY NOTES (answers to "is it a toy?")
  - Follows TCP streams (reassembled) and UDP streams. FTP: control creds appear
    in `creds`; follow the ftp-data stream by its id for transferred content.
  - Works on monitor-mode / 802.11 captures: `wifi` (beacons+probes) and `arp`
    activate when those frames are present. Handles VLAN, QUIC, IGMP, etc. — it
    dissects whatever tshark can, which is everything Wireshark understands.
  - For anything not surfaced by a section, `--filter` gives you the full power of
    Wireshark display filters, and `--stream` gives you raw reassembled payloads.

External software: tshark (Wireshark). Kali: `apt install tshark`. Windows dev
box: `C:\\Program Files\\Wireshark\\tshark.exe` (pass --tshark).

Safety: read-only. Reads a capture FILE; never captures live, never writes.

Usage:
    python -m forensics.pcap capture.pcap
    python -m forensics.pcap capture.pcap --sections tls,flows,creds --json
    python -m forensics.pcap capture.pcap --list-streams
    python -m forensics.pcap capture.pcap --stream 5
    python -m forensics.pcap capture.pcap --stream udp:3 --hex
    python -m forensics.pcap capture.pcap --filter "http.request && ip.addr==10.0.0.5"
"""

from __future__ import annotations

import argparse
import os
import sys

from common import proc
from common.output import emit, log

SECTIONS = ("summary", "proto", "hosts", "flows", "tls", "dns", "http", "dhcp",
            "files", "voip", "services", "arp", "wifi", "creds")
DEFAULT_SECTIONS = SECTIONS
_SEP = "\x1f"  # unit separator: safe column delimiter for -T fields


# --- tshark plumbing --------------------------------------------------------

def _tshark_bin(explicit: str | None) -> str:
    if explicit:
        return explicit
    if proc.have("tshark"):
        return "tshark"
    win = r"C:\Program Files\Wireshark\tshark.exe"
    return win if os.path.exists(win) else "tshark"


def _ensure(bin_: str) -> None:
    if not proc.have(bin_) and not os.path.exists(bin_):
        raise FileNotFoundError(
            f"tshark not found (tried {bin_!r}). Install Wireshark/tshark or pass --tshark."
        )


def _fields(bin_: str, path: str, fields: list[str], dfilter: str = "",
            timeout: float = 180) -> list[list[str]]:
    """Run tshark in -T fields mode; return rows. Tolerant: a bad field or a
    filter that matches nothing yields [] rather than raising."""
    argv = [bin_, "-r", path, "-n", "-T", "fields", "-E", f"separator={_SEP}"]
    if dfilter:
        argv += ["-Y", dfilter]
    for f in fields:
        argv += ["-e", f]
    ran = proc.run(argv, timeout=timeout)
    if not ran.found:
        raise FileNotFoundError(ran.stderr)
    rows = []
    for line in ran.stdout.splitlines():
        if line.strip():
            rows.append(line.split(_SEP))
    return rows


def _z(bin_: str, path: str, stat: str, timeout: float = 180) -> str:
    """Run a tshark -z statistics/utility and return raw stdout."""
    ran = proc.run([bin_, "-r", path, "-n", "-q", "-z", stat], timeout=timeout)
    if not ran.found:
        raise FileNotFoundError(ran.stderr)
    return ran.stdout


# --- digest sections --------------------------------------------------------

def _proto_hierarchy(bin_: str, path: str) -> list[str]:
    lines = [ln.rstrip() for ln in _z(bin_, path, "io,phs").splitlines() if ln.strip()]
    drop = {"Protocol Hierarchy Statistics"}
    return [ln for ln in lines if not set(ln) <= {"=", " "} and ln not in drop
            and not ln.startswith("Filter:")]


def _protocols_present(proto_lines: list[str]) -> list[str]:
    """The set of protocol names anywhere in the hierarchy (leaf + branch)."""
    names = set()
    for ln in proto_lines:
        tok = ln.strip().split()
        if tok and not tok[0].startswith("frames:"):
            names.add(tok[0])
    names.discard("frame")
    return sorted(names)


def _summary(bin_: str, path: str, proto_lines: list[str]) -> dict:
    times = _fields(bin_, path, ["frame.time_relative"])
    duration = 0.0
    if times and times[-1] and times[-1][0]:
        try:
            duration = round(float(times[-1][0]), 3)
        except ValueError:
            pass
    return {
        "packets": len(times),
        "duration_s": duration,
        "protocols": _protocols_present(proto_lines),
    }


def _flows(bin_: str, path: str, top: int = 25) -> list[dict]:
    """Top TCP/UDP flows with their stream IDs, annotated with SNI/host where
    known. The stream id is what you pass to --stream to follow it."""
    # SNI per TCP stream (from ClientHello) to label flows with a hostname.
    sni_map: dict[str, str] = {}
    for r in _fields(bin_, path, ["tcp.stream", "tls.handshake.extensions_server_name"],
                     "tls.handshake.type==1"):
        if len(r) >= 2 and r[0] and r[1]:
            sni_map.setdefault(r[0], r[1])

    flows: dict[tuple[str, str], dict] = {}
    for proto, sfield in (("tcp", "tcp"), ("udp", "udp")):
        rows = _fields(bin_, path,
                       [f"{sfield}.stream", "ip.src", f"{proto}.srcport",
                        "ip.dst", f"{proto}.dstport", "frame.len"], proto)
        for r in rows:
            r += [""] * (6 - len(r))
            sid, src, sp, dst, dp, ln = r[:6]
            if not sid:
                continue
            key = (proto, sid)
            f = flows.get(key)
            if f is None:
                f = flows[key] = {"proto": proto, "stream": int(sid) if sid.isdigit() else sid,
                                  "a": f"{src}:{sp}", "b": f"{dst}:{dp}",
                                  "packets": 0, "bytes": 0,
                                  "sni": sni_map.get(sid, "") if proto == "tcp" else ""}
            f["packets"] += 1
            f["bytes"] += int(ln) if ln.isdigit() else 0
    ranked = sorted(flows.values(), key=lambda f: f["bytes"], reverse=True)
    return ranked[:top]


def _tls(bin_: str, path: str) -> dict:
    sni = [r[0] for r in _fields(bin_, path, ["tls.handshake.extensions_server_name"],
                                 "tls.handshake.type==1") if r and r[0]]
    # QUIC also carries SNI in its TLS ClientHello.
    sni += [r[0] for r in _fields(bin_, path, ["tls.handshake.extensions_server_name"],
                                  "quic && tls.handshake.type==1") if r and r[0]]
    counts: dict[str, int] = {}
    for s in sni:
        counts[s] = counts.get(s, 0) + 1
    servers = [{"name": n, "hellos": c} for n, c in sorted(counts.items(),
               key=lambda kv: (-kv[1], kv[0]))]
    # Negotiated versions seen (ServerHello supported_versions or record version).
    vers = sorted({r[0] for r in _fields(bin_, path, ["tls.handshake.version"],
                   "tls.handshake.type==2") if r and r[0]})
    return {"server_names": servers, "versions": vers}


def _dns(bin_: str, path: str) -> list[dict]:
    rows = _fields(bin_, path, ["dns.qry.name", "dns.a", "dns.cname"],
                   "dns.flags.response==1 && !mdns")
    seen, out = set(), []
    for r in rows:
        name = r[0] if r else ""
        if not name:
            continue
        ans = (r[1] if len(r) > 1 else "") or (r[2] if len(r) > 2 else "")
        key = (name, ans)
        if key not in seen:
            seen.add(key)
            out.append({"query": name, "answer": ans})
    return out


def _http(bin_: str, path: str) -> dict:
    """HTTP requests/responses plus recon-relevant metadata: user-agents seen
    (client fingerprinting) and server banners."""
    transactions = []
    rows = _fields(bin_, path,
                   ["http.request.method", "http.host", "http.request.uri",
                    "http.response.code", "http.response.phrase"],
                   "http.request || http.response")
    for r in rows:
        r += [""] * (5 - len(r))
        method, host, uri, code, phrase = r[:5]
        if method:
            transactions.append({"kind": "req", "method": method, "host": host, "uri": uri})
        elif code:
            transactions.append({"kind": "resp", "status": code, "phrase": phrase})
    user_agents = sorted({r[0] for r in _fields(bin_, path, ["http.user_agent"],
                          "http.user_agent") if r and r[0]})
    servers = sorted({r[0] for r in _fields(bin_, path, ["http.server"], "http.server")
                      if r and r[0]})
    return {"transactions": transactions[:200], "user_agents": user_agents, "servers": servers}


def _services(bin_: str, path: str) -> list[dict]:
    out: list[dict] = []
    for r in _fields(bin_, path, ["dns.qry.name", "dns.resp.name"], "mdns"):
        name = (r[0] if r else "") or (r[1] if len(r) > 1 else "")
        if name:
            out.append({"proto": "mdns", "name": name})
    for r in _fields(bin_, path, ["dns.qry.name"], "llmnr"):
        if r and r[0]:
            out.append({"proto": "llmnr", "name": r[0]})
    for r in _fields(bin_, path, ["nbns.name"], "nbns"):
        if r and r[0]:
            out.append({"proto": "nbns", "name": r[0]})
    for r in _fields(bin_, path, ["http.location", "http.server"], "udp.port==1900"):
        val = (r[0] if r else "") or (r[1] if len(r) > 1 else "")
        if val:
            out.append({"proto": "ssdp", "name": val})
    # De-dup.
    seen, uniq = set(), []
    for s in out:
        k = (s["proto"], s["name"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


def _arp(bin_: str, path: str) -> list[dict]:
    out, seen = [], set()
    for r in _fields(bin_, path, ["arp.src.proto_ipv4", "arp.src.hw_mac",
                                  "arp.dst.proto_ipv4", "arp.opcode"], "arp"):
        r += [""] * (4 - len(r))
        sip, smac, dip, op = r[:4]
        key = (sip, smac, dip, op)
        if sip and key not in seen:
            seen.add(key)
            out.append({"src_ip": sip, "src_mac": smac, "dst_ip": dip,
                        "op": "request" if op == "1" else "reply" if op == "2" else op})
    return out


def _decode_ssid(raw: str) -> str:
    """tshark emits wlan.ssid as a hex string; decode to readable text. A hidden
    network shows as empty/<MISSING> -> report it as <hidden>."""
    if not raw or raw == "<MISSING>":
        return "<hidden>"
    try:
        text = bytes.fromhex(raw).decode("utf-8", "replace")
        # Wildcard/hidden probes are all-zero or empty once decoded.
        return text if text.strip("\x00").strip() else "<hidden>"
    except ValueError:
        return raw  # already text on some tshark builds


def _wifi(bin_: str, path: str) -> dict:
    """802.11 recon. Beacons list APs; hidden (cloaked) SSIDs are UNCOVERED by
    correlating the BSSID with probe responses and association requests, where a
    connecting client leaks the real name. EAPOL frames mean a WPA/WPA2 4-way
    handshake was captured (crackable offline with the right wordlist)."""
    # BSSID -> real SSID, learned from any frame type that carries a real name.
    revealed: dict[str, str] = {}
    for subtype in ("0x05", "0x00", "0x02", "0x08"):   # proberesp, assocreq, reassocreq, beacon
        for r in _fields(bin_, path, ["wlan.bssid", "wlan.ssid"],
                         f"wlan.fc.type_subtype=={subtype}"):
            r += [""] * (2 - len(r))
            bssid, name = r[0], _decode_ssid(r[1])
            if bssid and name != "<hidden>":
                revealed.setdefault(bssid, name)

    beacons, seen_b = [], set()
    for r in _fields(bin_, path, ["wlan.ssid", "wlan.bssid", "wlan_radio.channel"],
                     "wlan.fc.type_subtype==0x08"):
        r += [""] * (3 - len(r))
        ssid, bssid, chan = r[:3]
        if bssid and bssid not in seen_b:
            seen_b.add(bssid)
            beacon_ssid = _decode_ssid(ssid)
            hidden = beacon_ssid == "<hidden>"
            beacons.append({"bssid": bssid, "channel": chan,
                            "ssid": revealed.get(bssid, beacon_ssid),
                            "hidden": hidden,
                            "revealed": hidden and bssid in revealed})

    probes, seen_p = [], set()
    for r in _fields(bin_, path, ["wlan.ssid", "wlan.sa"], "wlan.fc.type_subtype==0x04"):
        r += [""] * (2 - len(r))
        ssid, sa = r[:2]
        key = (ssid, sa)
        if key not in seen_p:
            seen_p.add(key)
            probes.append({"ssid": _decode_ssid(ssid), "station": sa})

    # WPA handshake detection: which BSSIDs have EAPOL key frames.
    handshakes = sorted({r[0] for r in _fields(bin_, path, ["wlan.bssid"], "eapol") if r and r[0]})
    return {"beacons": beacons, "probe_requests": probes, "wpa_handshakes": handshakes}


def _creds(bin_: str, path: str) -> list[dict]:
    """Extract credentials/loot an operator can actually use: cleartext logins,
    crackable net-NTLM hashes, SNMP community strings, Kerberos principals, etc.
    Heuristic — every hit is a lead to confirm, but many are directly usable."""
    found: list[dict] = []
    seen: set = set()

    def add(kind, value, **kw):
        key = (kind, value)
        if value and key not in seen:
            seen.add(key)
            found.append({"kind": kind, "value": value, **kw})

    # --- net-NTLM (crackable with hashcat: v2=mode 5600, v1=mode 5500) ---
    # The server challenge (Type-2 CHALLENGE) and the client response (Type-3
    # AUTHENTICATE) are in different packets, so correlate them by TCP stream.
    challenges: dict[str, str] = {}
    for r in _fields(bin_, path, ["tcp.stream", "ntlmssp.ntlmserverchallenge"],
                     "ntlmssp.messagetype==0x00000002"):
        if len(r) >= 2 and r[0] and r[1]:
            challenges[r[0]] = r[1]
    for r in _fields(bin_, path,
                     ["tcp.stream", "ntlmssp.auth.domain", "ntlmssp.auth.username",
                      "ntlmssp.auth.ntresponse", "ntlmssp.auth.lmresponse"],
                     "ntlmssp.messagetype==0x00000003"):
        r += [""] * (5 - len(r))
        stream, domain, user, ntresp, lmresp = r[:5]
        chal = challenges.get(stream, "")
        if not (user and ntresp and chal) or user.upper() == "NULL":
            continue  # skip anonymous/null sessions (not crackable, not useful)
        if len(ntresp) > 48:                       # NTLMv2: 16B NTProofStr + blob
            proof, blob = ntresp[:32], ntresp[32:]
            add("ntlmv2", f"{user}::{domain}:{chal}:{proof}:{blob}", note="hashcat -m 5600")
        else:                                      # NTLMv1
            lm = lmresp or ntresp
            add("ntlmv1", f"{user}::{domain}:{lm}:{ntresp}:{chal}", note="hashcat -m 5500")

    # --- SNMP community strings (community == password) + SNMPv3 users ---
    for r in _fields(bin_, path, ["snmp.community"], "snmp.community"):
        if r and r[0]:
            add("snmp-community", r[0])
    for r in _fields(bin_, path, ["snmp.msgUserName"], "snmp.msgUserName"):
        if r and r[0]:
            add("snmpv3-user", r[0])

    # --- cleartext mail/login protocols ---
    for r in _fields(bin_, path, ["imap.request"], "imap.request"):
        if r and r[0] and "login" in r[0].lower():
            add("imap", r[0].strip()[:200])
    for r in _fields(bin_, path, ["pop.request.command", "pop.request.parameter"],
                     'pop.request.command=="USER" || pop.request.command=="PASS"'):
        r += [""] * (2 - len(r))
        add("pop", f"{r[0]} {r[1]}".strip())
    for r in _fields(bin_, path, ["smtp.req.parameter"], 'smtp.req.command=="AUTH"'):
        if r and r[0]:
            add("smtp-auth", r[0][:200])

    # --- Kerberos principals (kerberoast / AS-REP-roast leads) ---
    for r in _fields(bin_, path, ["kerberos.CNameString", "kerberos.realm"],
                     "kerberos.CNameString"):
        r += [""] * (2 - len(r))
        if r[0] and not r[0].endswith("$"):        # skip machine accounts
            add("kerberos-user", f"{r[0]}@{r[1]}")
    for r in _fields(bin_, path, ["kerberos.SNameString"], "kerberos.SNameString"):
        if r and r[0] and "/" in r[0]:             # SPNs are kerberoastable
            add("kerberos-spn", r[0])

    # --- RADIUS ---
    for r in _fields(bin_, path, ["radius.User_Name"], "radius.User_Name"):
        if r and r[0]:
            add("radius-user", r[0])

    # --- HTTP auth / form posts / cookies ---
    for r in _fields(bin_, path, ["http.authorization", "http.host"], "http.authorization"):
        if r and r[0]:
            add("http-authorization", r[0], host=r[1] if len(r) > 1 else "")
    for r in _fields(bin_, path, ["http.host", "http.file_data"], 'http.request.method=="POST"'):
        if len(r) > 1 and r[1] and ("pass" in r[1].lower() or "pwd" in r[1].lower()):
            add("http-post", r[1][:300], host=r[0])

    # --- FTP / Telnet ---
    for r in _fields(bin_, path, ["ftp.request.command", "ftp.request.arg"],
                     'ftp.request.command=="USER" || ftp.request.command=="PASS"'):
        if r and r[0]:
            add("ftp", f"{r[0]} {r[1] if len(r) > 1 else ''}".strip())
    for r in _fields(bin_, path, ["telnet.data"], 'telnet.data matches "(?i)(login|password)"'):
        if r and r[0]:
            add("telnet", r[0].strip()[:200])
    return found


def _hosts(bin_: str, path: str) -> list[dict]:
    """Build a host inventory (network map): IP <-> MAC <-> hostname, correlated
    from Ethernet, ARP, DHCP, and DNS. The single most useful 'what's on this
    network' view."""
    macs: dict[str, set] = {}
    names: dict[str, set] = {}
    _skip_ip = {"", "0.0.0.0", "255.255.255.255", "::"}
    _skip_mac = {"", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

    def _real_host(ip: str) -> bool:
        if ip in _skip_ip:
            return False
        first = ip.split(".")[0]
        return not (first.isdigit() and 224 <= int(first) <= 255)  # drop multicast/broadcast

    def bind_mac(ip, mac):
        if not _real_host(ip):
            return
        for m in (mac or "").split(","):            # a field may carry >1 value
            if m and m not in _skip_mac:
                macs.setdefault(ip, set()).add(m)

    def bind_name(ip, name):
        if _real_host(ip) and name:
            names.setdefault(ip, set()).add(name)

    for r in _fields(bin_, path, ["ip.src", "eth.src", "ip.dst", "eth.dst"], "ip && eth"):
        r += [""] * (4 - len(r))
        bind_mac(r[0], r[1])
        bind_mac(r[2], r[3])
    for r in _fields(bin_, path, ["arp.src.proto_ipv4", "arp.src.hw_mac"], "arp"):
        r += [""] * (2 - len(r))
        bind_mac(r[0], r[1])
    # DHCP: assigned IP + client MAC + hostname.
    for r in _fields(bin_, path, ["dhcp.ip.your", "dhcp.hw.mac_addr", "dhcp.option.hostname"],
                     "dhcp"):
        r += [""] * (3 - len(r))
        bind_mac(r[0], r[1])
        bind_name(r[0], r[2])
    # DNS A answers: hostname -> IP.
    for r in _fields(bin_, path, ["dns.qry.name", "dns.a"], "dns.a && dns.flags.response==1"):
        if len(r) >= 2 and r[0] and r[1]:
            for ip in r[1].split(","):
                bind_name(ip.strip(), r[0])

    hosts = []
    for ip in sorted(set(macs) | set(names), key=_ip_key):
        hosts.append({"ip": ip, "macs": sorted(macs.get(ip, [])),
                      "hostnames": sorted(names.get(ip, []))[:8]})
    return hosts


def _ip_key(ip: str):
    parts = ip.split(".")
    return tuple(int(p) for p in parts) if len(parts) == 4 and all(p.isdigit() for p in parts) else (999,)


def _dhcp(bin_: str, path: str) -> list[dict]:
    """DHCP leases/requests: MAC, hostname, requested/assigned IP, vendor class
    (device fingerprinting)."""
    out, seen = [], set()
    for r in _fields(bin_, path,
                     ["dhcp.hw.mac_addr", "dhcp.option.hostname",
                      "dhcp.option.requested_ip_address", "dhcp.ip.your",
                      "dhcp.option.vendor_class_id"], "dhcp"):
        r += [""] * (5 - len(r))
        mac, host, req_ip, your_ip, vendor = r[:5]
        ip = your_ip or req_ip
        key = (mac, host, ip, vendor)
        if mac and key not in seen:
            seen.add(key)
            out.append({"mac": mac, "hostname": host, "ip": ip, "vendor": vendor})
    return out


def _files(bin_: str, path: str) -> list[dict]:
    """Filenames/objects transferred: HTTP URIs & downloads, SMB files, TFTP, FTP."""
    out, seen = [], set()

    def add(proto, name):
        name = (name or "").strip()
        if name and (proto, name) not in seen:
            seen.add((proto, name))
            out.append({"proto": proto, "name": name})

    for r in _fields(bin_, path, ["http.host", "http.request.uri"], "http.request.uri"):
        r += [""] * (2 - len(r))
        uri = r[1]
        if uri and ("." in uri.rsplit("/", 1)[-1]):   # looks like it ends in a file
            add("http", f"{r[0]}{uri}"[:200])
    for r in _fields(bin_, path, ["http.content_disposition"], "http.content_disposition"):
        if r and r[0] and "filename" in r[0].lower():
            add("http-download", r[0][:150])
    for r in _fields(bin_, path, ["smb2.filename"], "smb2.filename"):
        if r and r[0]:
            add("smb", r[0])
    for r in _fields(bin_, path, ["smb.file"], "smb.file"):
        if r and r[0]:
            add("smb", r[0])
    for r in _fields(bin_, path, ["tftp.source_file", "tftp.destination_file"], "tftp"):
        r += [""] * (2 - len(r))
        add("tftp", r[0] or r[1])
    for r in _fields(bin_, path, ["ftp.request.arg"],
                     'ftp.request.command=="RETR" || ftp.request.command=="STOR"'):
        if r and r[0]:
            add("ftp", r[0])
    return out


def _voip(bin_: str, path: str) -> dict:
    """VoIP: SIP signaling (methods/parties/status) and RTP stream quality."""
    calls = []
    for r in _fields(bin_, path,
                     ["sip.Method", "sip.From.user", "sip.To.user",
                      "sip.Status-Code", "sip.CSeq.method"], "sip"):
        r += [""] * (5 - len(r))
        method, frm, to, status, cseq = r[:5]
        if method:
            calls.append({"type": "request", "method": method, "from": frm,
                          "to": to, "for": cseq})
        elif status:
            calls.append({"type": "response", "status": status, "for": cseq})
    # RTP stream quality via -z (SSRC, endpoints, loss, jitter).
    rtp = []
    text = _z(bin_, path, "rtp,streams")
    for line in text.splitlines():
        s = line.split()
        # data rows start with two float timestamps.
        if len(s) >= 10 and _isfloat(s[0]) and _isfloat(s[1]):
            try:
                rtp.append({"src": f"{s[2]}:{s[3]}", "dst": f"{s[4]}:{s[5]}",
                            "ssrc": s[6], "payload": s[7], "packets": s[8],
                            "lost": " ".join(s[9:11]) if "%" in line else s[9]})
            except IndexError:
                continue
    return {"calls": calls, "rtp_streams": rtp}


def _isfloat(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


# --- drill-down modes -------------------------------------------------------

def list_streams(path: str, *, tshark: str | None = None, proto: str = "tcp") -> list[dict]:
    """Index of streams for `proto` ("tcp" or "udp"): id, endpoints, packets, bytes.
    Feed a stream id to :func:`follow`."""
    bin_ = _tshark_bin(tshark)
    _ensure(bin_)
    if not os.path.exists(path):
        raise FileNotFoundError(f"capture not found: {path}")
    flows = [f for f in _flows(bin_, path, top=10**9) if f["proto"] == proto]
    return sorted(flows, key=lambda f: f["stream"] if isinstance(f["stream"], int) else 0)


def follow(path: str, stream: str, *, tshark: str | None = None, hexdump: bool = False) -> dict:
    """Reassemble and return one stream's content.

    Args:
        stream: TCP stream id ("5") or "udp:3" for a UDP stream.
        hexdump: hex+ascii instead of ascii (use for binary protocols).
    """
    bin_ = _tshark_bin(tshark)
    _ensure(bin_)
    if not os.path.exists(path):
        raise FileNotFoundError(f"capture not found: {path}")
    proto, _, sid = stream.partition(":")
    if not sid:
        proto, sid = "tcp", proto
    if proto not in ("tcp", "udp") or not sid.isdigit():
        raise ValueError(f"bad stream spec {stream!r}; use e.g. '5' or 'udp:3'")
    mode = "hex" if hexdump else "ascii"
    content = _z(bin_, path, f"follow,{proto},{mode},{sid}", timeout=120)
    return {"proto": proto, "stream": int(sid), "mode": mode, "content": content}


def filter_packets(path: str, dfilter: str, *, tshark: str | None = None,
                   limit: int = 500) -> dict:
    """Run a Wireshark display filter and return matching packets as summary lines
    (tshark's default one-line-per-packet view). `limit` caps the number returned."""
    bin_ = _tshark_bin(tshark)
    _ensure(bin_)
    if not os.path.exists(path):
        raise FileNotFoundError(f"capture not found: {path}")
    ran = proc.run([bin_, "-r", path, "-n", "-Y", dfilter], timeout=180)
    lines = [ln.rstrip() for ln in ran.stdout.splitlines() if ln.strip()]
    truncated = len(lines) > limit
    return {"filter": dfilter, "matched": len(lines), "truncated": truncated,
            "packets": lines[:limit]}


# --- digest orchestration ---------------------------------------------------

def run(path: str, *, sections: list[str] | None = None, tshark: str | None = None) -> dict:
    """Build the digest. See module docstring for section meanings.

    Returns {"file", "sections": {name: <data>}}. Raises FileNotFoundError if the
    capture or tshark is missing.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"capture not found: {path}")
    bin_ = _tshark_bin(tshark)
    _ensure(bin_)
    want = [s for s in (sections or DEFAULT_SECTIONS) if s in SECTIONS]

    proto_lines = _proto_hierarchy(bin_, path)
    present = set(_protocols_present(proto_lines))
    out: dict[str, object] = {}
    for name in want:
        # Skip sections whose protocols aren't in the capture (saves work).
        if name == "wifi" and not (present & {"wlan", "wlan_radio", "wlan_mgt"}):
            continue
        if name == "arp" and "arp" not in present:
            continue
        if name == "dhcp" and not (present & {"dhcp", "bootp"}):
            continue
        if name == "voip" and not (present & {"sip", "rtp", "rtcp", "rtp-midi"}):
            continue
        log(f"[*] {name} ...")
        builders = {
            "summary": lambda: _summary(bin_, path, proto_lines),
            "proto": lambda: proto_lines,
            "hosts": lambda: _hosts(bin_, path),
            "flows": lambda: _flows(bin_, path),
            "tls": lambda: _tls(bin_, path),
            "dns": lambda: _dns(bin_, path),
            "http": lambda: _http(bin_, path),
            "dhcp": lambda: _dhcp(bin_, path),
            "files": lambda: _files(bin_, path),
            "voip": lambda: _voip(bin_, path),
            "services": lambda: _services(bin_, path),
            "arp": lambda: _arp(bin_, path),
            "wifi": lambda: _wifi(bin_, path),
            "creds": lambda: _creds(bin_, path),
        }
        out[name] = builders[name]()
    return {"file": path, "sections": out}


def _compact_lines(res: dict) -> list[str]:
    s = res["sections"]
    lines = [f"# pcap: {res['file']}"]
    if "summary" in s:
        sm = s["summary"]
        lines.append(f"# packets: {sm['packets']}  duration: {sm['duration_s']}s")
        lines.append("# protocols: " + ", ".join(sm["protocols"]))
    if "proto" in s:
        lines.append("## protocol hierarchy")
        lines += s["proto"]
    if s.get("hosts"):
        lines.append("## hosts (ip  mac  hostname)")
        for h in s["hosts"]:
            lines.append(f"{h['ip']}  {','.join(h['macs']) or '-'}  {','.join(h['hostnames'])}".rstrip())
    if s.get("flows"):
        lines.append("## flows (proto/stream  a <-> b  pkts/bytes  sni)")
        for f in s["flows"]:
            label = f"  {f['sni']}" if f.get("sni") else ""
            lines.append(f"{f['proto']}/{f['stream']}  {f['a']} <-> {f['b']}  "
                         f"{f['packets']}/{f['bytes']}{label}")
    if s.get("tls"):
        t = s["tls"]
        if t["server_names"]:
            lines.append("## tls/quic server names (SNI)")
            lines += [f"{sn['name']} (x{sn['hellos']})" for sn in t["server_names"]]
        if t["versions"]:
            lines.append("# tls versions: " + ", ".join(t["versions"]))
    if s.get("dns"):
        lines.append("## dns")
        lines += [f"{d['query']} -> {d['answer']}" if d["answer"] else d["query"] for d in s["dns"]]
    if s.get("http"):
        h = s["http"]
        if h["transactions"]:
            lines.append("## http")
            for t in h["transactions"]:
                lines.append(f"{t['method']} {t['host']}{t['uri']}".rstrip() if t["kind"] == "req"
                             else f"<- {t['status']} {t.get('phrase','')}".rstrip())
        if h["user_agents"]:
            lines.append("# user-agents: " + " | ".join(h["user_agents"][:10]))
        if h["servers"]:
            lines.append("# http servers: " + ", ".join(h["servers"][:10]))
    if s.get("dhcp"):
        lines.append("## dhcp (mac  ip  hostname  vendor)")
        lines += [f"{d['mac']}  {d['ip']}  {d['hostname']}  {d['vendor']}".rstrip() for d in s["dhcp"]]
    if s.get("files"):
        lines.append("## files transferred")
        lines += [f"[{f['proto']}] {f['name']}" for f in s["files"]]
    if s.get("voip") and (s["voip"]["calls"] or s["voip"]["rtp_streams"]):
        lines.append("## voip")
        for c in s["voip"]["calls"]:
            lines.append(f"SIP {c['method']} {c.get('from','')} -> {c.get('to','')}".rstrip()
                         if c["type"] == "request" else f"SIP <- {c['status']} ({c.get('for','')})")
        for r in s["voip"]["rtp_streams"]:
            lines.append(f"RTP {r['src']} -> {r['dst']} ssrc={r['ssrc']} {r['payload']} "
                         f"pkts={r['packets']} lost={r['lost']}")
    if s.get("services"):
        lines.append("## service discovery")
        lines += [f"[{x['proto']}] {x['name']}" for x in s["services"]]
    if s.get("arp"):
        lines.append("## arp")
        lines += [f"{a['src_ip']} ({a['src_mac']}) {a['op']} {a['dst_ip']}".rstrip()
                  for a in s["arp"]]
    if s.get("wifi") and (s["wifi"]["beacons"] or s["wifi"]["probe_requests"]):
        w = s["wifi"]
        lines.append("## wifi 802.11")
        for b in w["beacons"]:
            tag = "  [SSID REVEALED]" if b.get("revealed") else ("  [hidden]" if b.get("hidden") else "")
            lines.append(f"beacon  {b['ssid']}  {b['bssid']}  ch{b['channel']}{tag}")
        lines += [f"probe   {p['ssid']}  <- {p['station']}" for p in w["probe_requests"]]
        if w.get("wpa_handshakes"):
            lines.append("# WPA/WPA2 EAPOL handshake captured (crackable) for: "
                         + ", ".join(w["wpa_handshakes"]))
    if s.get("creds"):
        lines.append("## LOOT / POSSIBLE CREDS")
        for c in s["creds"]:
            note = f"  ({c['note']})" if c.get("note") else ""
            host = f"{c['host']} " if c.get("host") else ""
            lines.append(f"[{c['kind']}] {host}{c['value']}{note}".strip())
    return lines


# --- CLI --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensics.pcap",
        description="Capable pcap/pcapng analysis for LLM operators (via tshark): "
                    "digest, follow streams, or run any Wireshark filter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "sections: " + ",".join(SECTIONS) + "\n\n"
            "examples:\n"
            "  python -m forensics.pcap capture.pcap\n"
            "  python -m forensics.pcap capture.pcap --sections tls,flows,creds --json\n"
            "  python -m forensics.pcap capture.pcap --list-streams\n"
            "  python -m forensics.pcap capture.pcap --stream 5\n"
            "  python -m forensics.pcap capture.pcap --stream udp:3 --hex\n"
            "  python -m forensics.pcap capture.pcap --filter 'http.request && ip.addr==10.0.0.5'\n"
        ),
    )
    p.add_argument("file", nargs="?", help="Path to a .pcap/.pcapng capture.")
    p.add_argument("--sections", metavar="A,B", help="Digest subset of: " + ",".join(SECTIONS))
    p.add_argument("--list-streams", action="store_true", help="List TCP stream ids to follow.")
    p.add_argument("--stream", metavar="ID", help="Follow a stream: '5' (tcp) or 'udp:3'.")
    p.add_argument("--hex", action="store_true", help="With --stream: hex+ascii (binary streams).")
    p.add_argument("--filter", metavar="DFILTER", help="Run a Wireshark display filter; return matches.")
    p.add_argument("--limit", type=int, default=500, help="Max packets for --filter (default 500).")
    p.add_argument("--tshark", metavar="PATH", help="Path to tshark if not on PATH.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.file:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        if args.list_streams:
            data = {"file": args.file, "streams": list_streams(args.file, tshark=args.tshark)}
            lines = ["# tcp streams (id  a <-> b  pkts/bytes  sni)"] + [
                f"{f['stream']}  {f['a']} <-> {f['b']}  {f['packets']}/{f['bytes']}"
                + (f"  {f['sni']}" if f["sni"] else "") for f in data["streams"]]
            emit(data, as_json=args.json, lines=lines)
        elif args.stream:
            data = follow(args.file, args.stream, tshark=args.tshark, hexdump=args.hex)
            emit(data, as_json=args.json,
                 lines=[f"# follow {data['proto']} stream {data['stream']} ({data['mode']})",
                        data["content"]])
        elif args.filter:
            data = filter_packets(args.file, args.filter, tshark=args.tshark, limit=args.limit)
            head = f"# filter: {data['filter']}  matched {data['matched']}" + (
                f" (showing {args.limit})" if data["truncated"] else "")
            emit(data, as_json=args.json, lines=[head] + data["packets"])
        else:
            secs = [x.strip() for x in args.sections.split(",")] if args.sections else None
            res = run(args.file, sections=secs, tshark=args.tshark)
            emit(res, as_json=args.json, lines=_compact_lines(res))
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
