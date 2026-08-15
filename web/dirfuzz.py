"""Content discovery (directory/file brute force) with soft-404 auto-calibration.

Finds hidden paths/files on a web server. The thing naive scanners get wrong is
soft-404s — apps that return 200 with a "not found" page for everything, drowning
you in false positives. This calibrates against random non-existent paths first,
learns the "not found" signature (status + body length), and filters it out, so the
hits it reports are real. Ships a compact high-signal default wordlist; point it at a
big list (e.g. SecLists on the box) with --wordlist for depth.

Dependencies: standard library only. No external API.

Safety: sends GET requests for candidate paths — active but non-intrusive (no
payloads, no writes). Rate is bounded by --workers. Only test authorized targets.

Usage:
    python -m web.dirfuzz https://target.example.com
    python -m web.dirfuzz https://target/ --wordlist /usr/share/wordlists/dirb/common.txt
    python -m web.dirfuzz https://target/ --ext php,txt,bak --json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import os
import sys
import urllib.request
from urllib.parse import urljoin

from common import http
from common.output import emit, log

# Compact, high-signal default list (sensitive files + common paths).
_DEFAULT = """\
admin administrator login logout register dashboard api api/v1 api/v2 graphql
.git/config .git/HEAD .env .env.local .env.prod config config.php config.json
wp-admin wp-login.php wp-config.php backup backup.zip backup.sql db.sql dump.sql
robots.txt sitemap.xml .htaccess .htpasswd server-status phpinfo.php info.php
uploads upload files images assets static js css test debug console actuator
actuator/health actuator/env metrics status health swagger swagger-ui.html
swagger.json openapi.json api-docs .well-known/security.txt crossdomain.xml
readme.md README.md CHANGELOG.md LICENSE .DS_Store web.config app.config
user users account settings profile private internal secret secrets tmp temp
old bak backups .svn/entries .bak index.php.bak composer.json package.json
docker-compose.yml Dockerfile .npmrc id_rsa .ssh/id_rsa cgi-bin""".split()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _fetch(url: str, timeout: float) -> tuple[int, int, str]:
    """GET without following redirects. Returns (status, body_len, location)."""
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": http.DEFAULT_UA})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536)
            return resp.status, len(body), resp.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(65536)
        except Exception:
            pass
        return exc.code, len(body), exc.headers.get("Location", "") if exc.headers else ""
    except Exception:
        return 0, 0, ""


def _calibrate(base: str, timeout: float) -> set[tuple[int, int]]:
    """Learn the soft-404 signature from random non-existent paths.
    Returns a set of (status, rounded_length) signatures to filter out."""
    sigs = set()
    for rnd in ("zzz-nope-9f8a71", "definitely-not-here-4b2c", "q${}random-x1y2z3"):
        st, ln, _ = _fetch(urljoin(base, rnd), timeout)
        if st:
            sigs.add((st, ln // 64))  # bucket lengths to tolerate minor variation
    return sigs


def _candidates(words: list[str], exts: list[str]) -> list[str]:
    out = []
    for w in words:
        out.append(w)
        if "." not in w.rsplit("/", 1)[-1]:      # add extensions to extensionless names
            for e in exts:
                out.append(f"{w}.{e}")
    return list(dict.fromkeys(out))


def run(base: str, *, wordlist: str = "", exts: list[str] | None = None,
        workers: int = 30, timeout: float = 8.0) -> dict:
    """Fuzz ``base`` for paths. Returns discovered hits (soft-404-filtered)."""
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    if not base.endswith("/"):
        base += "/"
    words = _DEFAULT
    if wordlist:
        with open(wordlist, encoding="utf-8", errors="ignore") as fh:
            words = [ln.strip().lstrip("/") for ln in fh if ln.strip() and not ln.startswith("#")]
    cands = _candidates(words, exts or [])

    log(f"[*] calibrating soft-404 baseline ...")
    soft404 = _calibrate(base, timeout)
    log(f"[*] fuzzing {len(cands)} paths (soft-404 sig: {sorted(soft404)}) ...")

    hits = []
    def probe(path):
        st, ln, loc = _fetch(urljoin(base, path), timeout)
        if st == 0 or st == 404:
            return None
        if (st, ln // 64) in soft404:            # matches the not-found signature
            return None
        return {"path": path, "status": st, "length": ln, "location": loc}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(cands))) as pool:
        for r in pool.map(probe, cands):
            if r:
                hits.append(r)
    # Sort: 200s first, then auth-gated (401/403), then redirects, then errors.
    def rank(h):
        s = h["status"]
        return (0 if s == 200 else 1 if s in (401, 403) else 2 if 300 <= s < 400 else 3, h["path"])
    hits.sort(key=rank)
    return {"base": base, "tested": len(cands), "soft404_sig": sorted(soft404),
            "hits": hits}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# dirfuzz: {res['base']}  ({res['tested']} tested, {len(res['hits'])} found)"]
    if res["hits"]:
        for h in res["hits"]:
            extra = f"  -> {h['location']}" if h["location"] else ""
            flag = "[!] " if h["status"] in (200, 401, 403) or h["path"].startswith(".") else "    "
            lines.append(f"{flag}{h['status']}  {h['length']:>7}b  /{h['path']}{extra}")
    else:
        lines.append("# nothing found beyond the soft-404 baseline")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.dirfuzz", description="Directory/file discovery with soft-404 filtering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m web.dirfuzz https://target\n"
               "  python -m web.dirfuzz https://target --wordlist /usr/share/wordlists/dirb/common.txt\n")
    p.add_argument("base", nargs="?", help="Base URL.")
    p.add_argument("--wordlist", default="", help="Path to a wordlist (else built-in list).")
    p.add_argument("--ext", default="", help="Comma extensions to append, e.g. php,txt,bak.")
    p.add_argument("--workers", type=int, default=30)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.base:
        build_parser().print_help(sys.stderr)
        return 2
    exts = [e.strip() for e in args.ext.split(",") if e.strip()] if args.ext else []
    try:
        res = run(args.base, wordlist=args.wordlist, exts=exts,
                  workers=args.workers, timeout=args.timeout)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
