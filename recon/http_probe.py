"""Probe hosts over HTTP(S) and return one compact line per live host.

The recon glue between "I have 500 subdomains" and "these 10 are worth looking
at". For each target it tries HTTPS then HTTP, follows redirects (recording the
chain), and reports status, page title, server banner, redirect target, content
length, and a light technology guess. Turns a huge host list into a triaged,
skimmable table an LLM can act on.

Feed it a single host, an explicit list (--hosts/--stdin), or a domain with
--enum to enumerate subdomains first (via recon.subdomains) and probe them all.

Dependencies: standard library only (urllib). No external API. Connects directly
to each target.

Safety: read-only. Sends benign GET requests to the target's web ports and reads
the response. No fuzzing, no payloads, nothing written. Still: only probe hosts
you're authorized to test.

Usage:
    python -m recon.http_probe example.com
    python -m recon.http_probe example.com --enum --json
    python -m recon.http_probe --hosts hosts.txt
    cat hosts.txt | python -m recon.http_probe --stdin --show-dead
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import html
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from common.output import emit, log
from common.validate import domain as norm_domain

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 recon-http-probe"
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CHARSET_RE = re.compile(rb'charset=["\']?([\w-]+)', re.IGNORECASE)
_GENERATOR_RE = re.compile(
    rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)

_MAX_BODY = 65536       # read only the head of the body; titles live near the top
_MAX_REDIRECTS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Suppress urllib's auto-follow so we can record the chain ourselves."""
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect())


def _decode_title(body: bytes, ctype: str) -> str:
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    enc = "utf-8"
    cm = _CHARSET_RE.search(body) or _CHARSET_RE.search(ctype.encode())
    if cm:
        enc = cm.group(1).decode("ascii", "ignore") or "utf-8"
    title = html.unescape(m.group(1).decode(enc, "replace"))
    return re.sub(r"\s+", " ", title).strip()[:200]


def _guess_tech(headers: dict[str, str], body: bytes) -> list[str]:
    """Light, high-signal technology fingerprinting from headers + body markers."""
    tech: list[str] = []
    hay = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    markers = {
        "cloudflare": "cloudflare", "nginx": "nginx", "apache": "apache",
        "iis": "microsoft-iis", "php": "php", "express": "express",
        "wordpress": "wp-", "drupal": "drupal", "joomla": "joomla",
        "asp.net": "asp.net", "tomcat": "tomcat", "gunicorn": "gunicorn",
        "openresty": "openresty", "litespeed": "litespeed",
    }
    for name, needle in markers.items():
        if needle in hay:
            tech.append(name)
    gm = _GENERATOR_RE.search(body)
    if gm:
        tech.append("generator:" + gm.group(1).decode("ascii", "ignore")[:40])
    low = body[:_MAX_BODY].lower()
    if b"wp-content" in low or b"wp-includes" in low:
        tech.append("wordpress")
    if b"x-drupal" in hay.encode() or b"drupal-settings" in low:
        tech.append("drupal")
    return sorted(set(tech))


def _fetch(url: str, timeout: float) -> dict | None:
    """GET ``url`` without auto-redirect. Returns a response dict or None if the
    connection failed entirely (dead)."""
    opener = _opener()
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        resp = opener.open(req, timeout=timeout)
        raw = resp.read(_MAX_BODY)
        status, headers, final = resp.status, dict(resp.headers), resp.geturl()
    except urllib.error.HTTPError as exc:      # 4xx/5xx are "alive"
        raw = b""
        try:
            raw = exc.read(_MAX_BODY)
        except Exception:
            pass
        status, headers, final = exc.code, dict(exc.headers or {}), url
    except (urllib.error.URLError, TimeoutError, OSError, Exception):
        return None
    if headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    return {"status": status, "headers": {k.lower(): v for k, v in headers.items()},
            "body": raw, "final": final}


def probe_host(host: str, *, timeout: float = 8.0, prefer_https: bool = True) -> dict:
    """Probe one host: try HTTPS then HTTP, follow redirects manually, summarize.

    Returns a dict with: host, alive (bool), url (scheme that worked), status,
    title, server, content_length, content_type, redirects (list of urls),
    final_url, tech (list). alive=False means neither scheme responded.
    """
    schemes = ("https", "http") if prefer_https else ("http", "https")
    for scheme in schemes:
        url = f"{scheme}://{host}/"
        chain: list[str] = []
        current = url
        resp = None
        for _ in range(_MAX_REDIRECTS + 1):
            resp = _fetch(current, timeout)
            if resp is None:
                break
            if 300 <= resp["status"] < 400 and resp["headers"].get("location"):
                nxt = urljoin(current, resp["headers"]["location"])
                chain.append(nxt)
                current = nxt
                continue
            break
        if resp is None:
            continue  # this scheme dead; try the other
        h = resp["headers"]
        return {
            "host": host, "alive": True, "url": url,
            "status": resp["status"],
            "title": _decode_title(resp["body"], h.get("content-type", "")),
            "server": h.get("server", ""),
            "content_length": h.get("content-length", str(len(resp["body"]))),
            "content_type": h.get("content-type", "").split(";")[0],
            "redirects": chain,
            "final_url": current,
            "tech": _guess_tech(h, resp["body"]),
        }
    return {"host": host, "alive": False, "url": "", "status": None, "title": "",
            "server": "", "content_length": "", "content_type": "",
            "redirects": [], "final_url": "", "tech": []}


def run(targets: list[str], *, timeout: float = 8.0, workers: int = 40) -> dict:
    """Probe every host in ``targets`` concurrently.

    Returns {"count", "live", "results": [probe_host dict, ...] sorted host}.
    """
    hosts = sorted({t.strip().lower() for t in targets if t.strip()})
    results: list[dict] = []
    log(f"[*] probing {len(hosts)} hosts (timeout={timeout}s) ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(hosts) or 1)) as pool:
        futs = {pool.submit(probe_host, h, timeout=timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:  # a bad host must not kill the run
                results.append({"host": futs[fut], "alive": False, "error": str(exc),
                                "status": None, "title": "", "server": "",
                                "content_length": "", "content_type": "",
                                "redirects": [], "final_url": "", "url": "", "tech": []})
    results.sort(key=lambda r: r["host"])
    return {"count": len(hosts), "live": sum(1 for r in results if r["alive"]),
            "results": results}


def _compact_lines(res: dict, show_dead: bool) -> list[str]:
    lines = [f"# http_probe: {res['count']} targets, {res['live']} live"]
    for r in res["results"]:
        if not r["alive"]:
            if show_dead:
                lines.append(f"{r['host']}  [dead]")
            continue
        parts = [f"{r['url']}", f"[{r['status']}]"]
        if r["title"]:
            parts.append(f'"{r["title"]}"')
        if r["server"]:
            parts.append(f"server={r['server']}")
        if r["content_length"]:
            parts.append(f"len={r['content_length']}")
        if r["redirects"]:
            parts.append(f"-> {r['final_url']}")
        if r["tech"]:
            parts.append(f"[tech: {','.join(r['tech'])}]")
        lines.append("  ".join(parts))
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.http_probe",
        description="Probe hosts over HTTP(S); one compact line per live host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m recon.http_probe example.com\n"
            "  python -m recon.http_probe example.com --enum --json\n"
            "  python -m recon.http_probe --hosts hosts.txt --show-dead\n"
            "  cat hosts.txt | python -m recon.http_probe --stdin\n"
        ),
    )
    p.add_argument("target", nargs="?", help="A host to probe, or a domain with --enum.")
    p.add_argument("--enum", action="store_true",
                   help="Treat target as a domain: enumerate subdomains first, then probe all.")
    p.add_argument("--hosts", metavar="FILE", help="File with one host per line.")
    p.add_argument("--stdin", action="store_true", help="Read hosts (one per line) from stdin.")
    p.add_argument("--show-dead", action="store_true", help="Also list hosts that didn't respond.")
    p.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout (s).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets: list[str] = []
    if args.hosts:
        try:
            with open(args.hosts, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if args.stdin and not sys.stdin.isatty():
        targets += [ln.strip() for ln in sys.stdin if ln.strip()]
    if args.target:
        if args.enum:
            try:
                d = norm_domain(args.target)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            from recon.subdomains import run as enum
            log(f"[*] enumerating {d} ...")
            targets += enum(d)["subdomains"] + [d]
        else:
            targets.append(args.target)

    if not targets:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(targets, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res, args.show_dead))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
