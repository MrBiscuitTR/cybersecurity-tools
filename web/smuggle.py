"""Detect HTTP request smuggling / desync (CL.TE and TE.CL) via safe timing tests.

When a front-end and back-end disagree about where a request ends (Content-Length vs
Transfer-Encoding), an attacker can smuggle a request prefix that poisons the next
user's request — one of the highest-impact web bugs. This detects the disagreement
with James Kettle's timing method: a crafted request makes the back-end WAIT for more
data if (and only if) it parses the length differently than the front-end. A large,
consistent delay versus a fast baseline = a desync.

This is DETECTION ONLY and self-contained: the payloads make the target's own
connection hang; they do NOT smuggle a request that affects other users (that's the
exploitation step, which needs care and permission). Uses raw sockets because the
malformed CL/TE headers can't be sent through a normal HTTP client.

Dependencies: standard library only. No external API.

Safety: sends a few crafted requests to the target and times them; no writes, no
cross-user impact. Only test authorized targets.

Usage:
    python -m web.smuggle https://target.example.com/
    python -m web.smuggle https://target.example.com/ --json
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

_DELAY_THRESHOLD = 5.0   # seconds of extra latency that indicates a hang
_SOCKET_TIMEOUT = 12.0


def _raw(host: str, port: int, use_ssl: bool, payload: bytes, timeout: float) -> float:
    """Send raw bytes, read until first response or timeout; return elapsed seconds."""
    t0 = time.time()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        try:
            sock.recv(2048)
        except (socket.timeout, TimeoutError):
            pass  # hung -> elapsed ~ timeout
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return time.time() - t0


def _payloads(host: str, path: str) -> dict[str, bytes]:
    """Baseline plus the CL.TE and TE.CL timing probes (and a TE obfuscation)."""
    def req(headers: str, body: str) -> bytes:
        return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n{headers}"
                f"Connection: keep-alive\r\n\r\n{body}").encode()
    return {
        # A well-formed, complete request — must return FAST (empty body, CL matches).
        "baseline": req("Content-Length: 0\r\n", ""),
        # CL.TE: front-end uses CL(4) and forwards a truncated body; back-end uses TE
        # (chunked) and waits for the next chunk -> hang if back-end honors TE.
        "CL.TE": req("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "1\r\nA\r\nX"),
        # TE.CL: front-end uses TE (ends at 0-chunk); back-end uses CL(6) and waits for
        # the 6th byte that never arrives -> hang if back-end honors CL.
        "TE.CL": req("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n", "0\r\n\r\nX"),
        # TE header obfuscation (space before colon) — bypasses naive TE parsers.
        "TE.CL(obf)": req("Content-Length: 6\r\nTransfer-Encoding : chunked\r\n", "0\r\n\r\nX"),
    }


def run(url: str, *, rounds: int = 2, timeout: float = _SOCKET_TIMEOUT) -> dict:
    parts = urlparse(url if "://" in url else "https://" + url)
    use_ssl = parts.scheme != "http"
    host = parts.hostname
    port = parts.port or (443 if use_ssl else 80)
    path = parts.path or "/"
    payloads = _payloads(host, path)

    # Establish a baseline latency (median of a couple normal requests).
    base_times = []
    for _ in range(rounds):
        try:
            base_times.append(_raw(host, port, use_ssl, payloads["baseline"], timeout))
        except OSError as exc:
            return {"url": url, "error": f"connect failed: {exc}", "findings": []}
    baseline = min(base_times)

    findings = []
    for name in ("CL.TE", "TE.CL", "TE.CL(obf)"):
        # Require the delay to reproduce across rounds to cut false positives.
        delays = []
        for _ in range(rounds):
            try:
                delays.append(_raw(host, port, use_ssl, payloads[name], timeout))
            except OSError:
                delays.append(0.0)
        worst = min(delays)  # min: a real hang delays EVERY round
        extra = worst - baseline
        if extra >= _DELAY_THRESHOLD:
            findings.append({"type": name, "baseline_s": round(baseline, 2),
                             "delayed_s": round(worst, 2), "extra_s": round(extra, 2),
                             "level": "high"})
    return {"url": url, "baseline_s": round(baseline, 2),
            "vulnerable": bool(findings), "findings": findings}


def _compact_lines(res: dict) -> list[str]:
    if res.get("error"):
        return [f"# smuggle: {res['url']}  error: {res['error']}"]
    lines = [f"# smuggle: {res['url']}  "
             f"{'DESYNC DETECTED' if res['vulnerable'] else 'no desync detected'}",
             f"# baseline latency: {res['baseline_s']}s"]
    if res["findings"]:
        lines.append("## FINDINGS")
        for f in res["findings"]:
            lines.append(f"[HIGH] {f['type']} desync — request hung {f['delayed_s']}s "
                         f"(+{f['extra_s']}s over baseline). Verify manually before exploiting.")
    else:
        lines.append("# (timing consistent; no CL/TE parsing disagreement observed)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.smuggle", description="Detect HTTP request smuggling (CL.TE/TE.CL) by timing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python -m web.smuggle https://target/\n")
    p.add_argument("url", nargs="?", help="Target URL.")
    p.add_argument("--rounds", type=int, default=2, help="Repeat each probe N times (default 2).")
    p.add_argument("--timeout", type=float, default=_SOCKET_TIMEOUT)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.url, rounds=args.rounds, timeout=args.timeout)
    emit_lines = _compact_lines(res)
    from common.output import emit
    emit(res, as_json=args.json, lines=emit_lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
