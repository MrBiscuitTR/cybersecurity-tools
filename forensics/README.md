# forensics

Analysis of artifacts left behind on disk or in captures.

Fits here: file/image metadata extraction, log parsing and timelining, packet
capture analysis, file carving, hash-based file identification.

## Tools

- **[pcap.py](pcap.py)** — capable pcap/pcapng analysis via `tshark`, built to
  hand an LLM operator real, usable recon/loot. Three modes:

  - **digest** (default) — compact sections, each auto-skipped when empty:
    - `summary` (packets/duration/protocols present), `proto` (hierarchy)
    - `hosts` — network inventory: IP ↔ MAC ↔ hostname (from Ethernet/ARP/DHCP/DNS)
    - `flows` — top TCP/UDP flows with **stream IDs** + SNI (feed to follow)
    - `tls` — TLS/QUIC SNI (who was contacted) + versions
    - `dns`, `http` (+ user-agents/servers), `dhcp` (leases/vendor), `files`
    - `voip` — SIP signaling + RTP stream quality (loss/jitter)
    - `services` (mDNS/LLMNR/NBNS/SSDP), `arp`
    - `wifi` — beacons/probes, **hidden-SSID reveal** (from probe-resp/assoc),
      and **WPA/WPA2 handshake detection** (crackable)
    - `creds` — **loot**: cleartext logins (HTTP/FTP/Telnet/IMAP/POP/SMTP), SNMP
      community strings, Kerberos principals/SPNs, and **crackable net-NTLM
      hashes formatted for hashcat** (v1=5500, v2=5600)
  - **follow a stream** — `--stream 5` / `--stream udp:3` reassembles a full
    conversation (HTTP exchange, FTP-DATA, telnet session, …).
  - **display filter** — `--filter "<wireshark filter>"` returns matching packets;
    the escape hatch for anything a section doesn't surface.

  ```bash
  python -m forensics.pcap capture.pcap
  python -m forensics.pcap capture.pcap --sections creds,hosts,files --json
  python -m forensics.pcap capture.pcap --list-streams
  python -m forensics.pcap capture.pcap --stream 5
  python -m forensics.pcap capture.pcap --filter "ntlmssp || kerberos"
  # Windows (tshark not on PATH):
  python -m forensics.pcap capture.pcap --tshark "/c/Program Files/Wireshark/tshark.exe"
  ```

  Requires `tshark` (Wireshark). On Kali: `apt install tshark`.

- **[log_triage.py](log_triage.py)** — triage auth/web-server logs: SSH brute-force
  sources + successful logins, web attack payloads (SQLi/XSS/traversal/RCE/LFI/
  log4shell), scanner user-agents, and status/volume anomalies. Stdlib-only.

  ```bash
  python -m forensics.log_triage /var/log/auth.log
  python -m forensics.log_triage access.log --json
  ```
