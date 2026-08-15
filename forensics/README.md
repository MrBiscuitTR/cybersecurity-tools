# forensics

Analysis of artifacts left behind on disk or in captures.

Fits here: file/image metadata extraction, log parsing and timelining, packet
capture analysis, file carving, hash-based file identification.

## Tools

- **[pcap.py](pcap.py)** — compact, LLM-friendly digest of a pcap/pcapng capture
  via `tshark`. Sections: summary, protocol hierarchy, top talkers, DNS, HTTP,
  and heuristic cleartext creds. Returns kilobytes for even a large capture, so
  it fits a context window. Read-only; reads a file, never captures live.

  ```bash
  python -m forensics.pcap capture.pcap
  python -m forensics.pcap capture.pcap --sections dns,creds --json
  # Windows (tshark not on PATH):
  python -m forensics.pcap capture.pcap --tshark "/c/Program Files/Wireshark/tshark.exe"
  ```

  Requires `tshark` (Wireshark). On Kali: `apt install tshark`.
