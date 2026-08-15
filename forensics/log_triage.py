"""Triage auth/web server logs — surface attacks and anomalies for an LLM.

Parses common log formats and flags the things worth acting on: SSH brute-force
sources and successful logins, web attack payloads (SQLi/XSS/traversal/RCE/LFI)
in access logs, scanner user-agents, and error/status anomalies. Log-reading is
pure pattern-matching — an LLM sweet spot — but a big log is too much to eyeball;
this distills it to a compact, ranked summary.

Handles, auto-detected per line:
  - syslog auth (sshd): "Failed password", "Accepted ...", "Invalid user"
  - Apache/Nginx access (common/combined): IP, method, path, status, UA

Dependencies: standard library only. No external API. Reads a local log file.

Safety: read-only. Parses a file you give it; changes nothing.

Usage:
    python -m forensics.log_triage /var/log/auth.log
    python -m forensics.log_triage access.log --json
    python -m forensics.log_triage access.log --top 20
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict

from common.output import emit

# --- SSH auth log patterns --------------------------------------------------
_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
_SSH_OK = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
_SSH_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")

# --- access log pattern (common + combined) ---------------------------------
_ACCESS = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>[^"]*?) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

# --- web attack signatures (in the request path/query) ----------------------
_ATTACKS = [
    ("sqli", re.compile(r"(?i)(union\s+select|\bor\s+1=1\b|'\s*or\s*'|information_schema|"
                        r"sleep\(|benchmark\(|;--|/\*.*\*/)")),
    ("xss", re.compile(r"(?i)(<script|onerror=|onload=|javascript:|%3cscript|alert\()")),
    ("traversal", re.compile(r"(?i)(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|/etc/shadow|boot\.ini)")),
    ("rce", re.compile(r"(?i)(;\s*(?:wget|curl|bash|sh|nc|python)|\|\s*(?:sh|bash)|"
                       r"\$\(|`.*`|/bin/(?:sh|bash))")),
    ("lfi-rfi", re.compile(r"(?i)(php://|data://|expect://|=https?://|file=/)")),
    ("log4shell", re.compile(r"(?i)\$\{jndi:")),
]
_SCANNER_UA = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|feroxbuster|ffuf|wpscan|"
    r"acunetix|nessus|nuclei|zgrab|python-requests|go-http-client|curl/|libwww)")


def run(path: str, *, top: int = 15) -> dict:
    """Parse and triage the log at ``path``. Returns a dict of findings."""
    ssh_fail = Counter()            # ip -> failed attempts
    ssh_users = defaultdict(set)    # ip -> usernames tried
    ssh_ok = []                     # (user, ip)
    invalid_users = Counter()

    web_attacks = []                # {type, ip, method, path, status}
    scanners = Counter()            # ua-family -> count
    scanner_ips = defaultdict(set)
    status_counts = Counter()
    ip_hits = Counter()
    lines = 0

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines += 1
            m = _SSH_FAIL.search(line)
            if m:
                ssh_fail[m.group(2)] += 1
                ssh_users[m.group(2)].add(m.group(1))
                continue
            m = _SSH_OK.search(line)
            if m:
                ssh_ok.append((m.group(1), m.group(2)))
                continue
            m = _SSH_INVALID.search(line)
            if m:
                invalid_users[m.group(1)] += 1
                continue
            m = _ACCESS.match(line)
            if m:
                ip, path_q, status = m.group("ip"), m.group("path"), m.group("status")
                ua = m.group("ua") or ""
                ip_hits[ip] += 1
                status_counts[status] += 1
                for atype, rx in _ATTACKS:
                    if rx.search(path_q):
                        web_attacks.append({"type": atype, "ip": ip,
                                            "method": m.group("method"),
                                            "path": path_q[:160], "status": status})
                        break
                sm = _SCANNER_UA.search(ua)
                if sm:
                    fam = sm.group(1).lower().rstrip("/")
                    scanners[fam] += 1
                    scanner_ips[fam].add(ip)

    # Rank SSH brute-forcers (>=5 failures is the usual threshold).
    brute = [{"ip": ip, "fails": n, "users": sorted(ssh_users[ip])[:8]}
             for ip, n in ssh_fail.most_common(top) if n >= 5]
    attack_by_type = Counter(a["type"] for a in web_attacks)
    return {
        "file": path, "lines": lines,
        "ssh": {
            "brute_force": brute,
            "successful_logins": [{"user": u, "ip": i} for u, i in ssh_ok][:top],
            "top_invalid_users": invalid_users.most_common(top),
        },
        "web": {
            "attacks": web_attacks[:200],
            "attacks_by_type": dict(attack_by_type),
            "scanners": [{"tool": t, "requests": c, "ips": sorted(scanner_ips[t])[:5]}
                         for t, c in scanners.most_common(top)],
            "top_ips": ip_hits.most_common(top),
            "status_codes": dict(sorted(status_counts.items())),
        },
    }


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# log_triage: {res['file']}  ({res['lines']} lines)"]
    ssh = res["ssh"]
    if ssh["brute_force"]:
        lines.append("## SSH BRUTE-FORCE sources")
        lines += [f"[!] {b['ip']}  {b['fails']} fails  users={','.join(b['users'])}"
                  for b in ssh["brute_force"]]
    if ssh["successful_logins"]:
        lines.append("## SSH successful logins")
        lines += [f"{l['user']}@{l['ip']}" for l in ssh["successful_logins"]]
    if ssh["top_invalid_users"]:
        lines.append("# invalid users tried: "
                     + ", ".join(f"{u}({n})" for u, n in ssh["top_invalid_users"]))
    web = res["web"]
    if web["attacks"]:
        lines.append(f"## WEB ATTACKS  ({web['attacks_by_type']})")
        for a in web["attacks"][:60]:
            lines.append(f"[{a['type']}] {a['ip']}  {a['method']} {a['path']}  -> {a['status']}")
    if web["scanners"]:
        lines.append("## scanners")
        lines += [f"{s['tool']}  {s['requests']} reqs  from {','.join(s['ips'])}"
                  for s in web["scanners"]]
    if web["top_ips"]:
        lines.append("# top IPs: " + ", ".join(f"{ip}({n})" for ip, n in web["top_ips"][:10]))
    if web["status_codes"]:
        lines.append("# status codes: "
                     + ", ".join(f"{k}={v}" for k, v in web["status_codes"].items()))
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensics.log_triage",
        description="Triage auth/web logs: brute force, web attacks, scanners, anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m forensics.log_triage /var/log/auth.log\n"
                "  python -m forensics.log_triage access.log --json\n"),
    )
    p.add_argument("file", nargs="?", help="Log file to triage (auth or access log).")
    p.add_argument("--top", type=int, default=15, help="Max entries per ranking (default 15).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.file:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.file, top=args.top)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
