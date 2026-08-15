"""Compute a site's favicon hash and hand back Shodan/FOFA/Censys pivots.

A favicon is often shared across all of an organization's infrastructure — even
hosts with no other link. Shodan/FOFA index favicons by a MurmurHash3 hash, so one
favicon hash pivots to every other host serving the same icon (hidden origins,
staging, related companies). This computes that hash (Shodan's exact scheme) and
emits ready-to-run search queries.

MurmurHash3 (x86 32-bit) is implemented here in pure Python, so there's no ``mmh3``
dependency. Shodan's hash = ``mmh3.hash(base64.encodebytes(favicon_bytes))``.

Dependencies: standard library only. No API key needed to COMPUTE the hash; the
emitted Shodan/FOFA queries are what you run (those platforms may need an account).

Safety: read-only. Fetches the favicon over HTTP(S); nothing else.

Usage:
    python -m recon.favicon https://example.com
    python -m recon.favicon https://example.com/favicon.ico --json
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from urllib.parse import urljoin, urlparse

from common import http
from common.output import emit, log

_ICON_LINK = re.compile(r"""<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*>""", re.I)
_HREF = re.compile(r"""href=["']([^"']+)["']""", re.I)


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned as a SIGNED int (Shodan's convention)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = int.from_bytes(data[i:i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(favicon_bytes: bytes) -> int:
    """Shodan's favicon hash: mmh3 over the base64 (with newlines) of the bytes."""
    return murmur3_x86_32(base64.encodebytes(favicon_bytes))


def _find_favicon_url(page_url: str, timeout: float) -> str:
    """Return the favicon URL for a page: parse <link rel=icon>, else /favicon.ico."""
    r = http.get(page_url, timeout=timeout, retries=1)
    if r.ok:
        m = _ICON_LINK.search(r.text)
        if m:
            href = _HREF.search(m.group(0))
            if href:
                return urljoin(page_url, href.group(1))
    base = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"
    return base + "/favicon.ico"


def run(target: str, *, timeout: float = 12.0) -> dict:
    """Fetch ``target``'s favicon and compute its hash + search pivots.

    ``target`` may be a page URL or a direct favicon URL.
    """
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    icon_url = target if target.lower().rstrip("/").endswith((".ico", ".png")) \
        else _find_favicon_url(target, timeout)
    log(f"[*] fetching favicon: {icon_url}")
    r = http.get(icon_url, timeout=timeout, retries=1)
    if not r.ok or not r.body:
        raise ValueError(f"could not fetch favicon at {icon_url} ({r.error or r.status})")
    h = favicon_hash(r.body)
    return {
        "target": target, "favicon_url": icon_url, "bytes": len(r.body),
        "content_type": r.body[:8].hex(), "hash": h,
        "pivots": {
            "shodan": f'http.favicon.hash:{h}',
            "fofa": f'icon_hash="{h}"',
            "censys": f'services.http.response.favicons.md5_hash (compute md5 separately)',
            "zoomeye": f'iconhash:"{h}"',
        },
    }


def _compact_lines(res: dict) -> list[str]:
    return [
        f"# favicon: {res['target']}",
        f"# url: {res['favicon_url']}  ({res['bytes']} bytes)",
        f"# mmh3 hash: {res['hash']}",
        "## pivots (search these to find hosts sharing this favicon)",
        f"  shodan:  {res['pivots']['shodan']}",
        f"  fofa:    {res['pivots']['fofa']}",
        f"  zoomeye: {res['pivots']['zoomeye']}",
    ]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.favicon",
        description="Compute a site's favicon hash (Shodan mmh3) and emit search pivots.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m recon.favicon https://example.com\n"
                "  python -m recon.favicon https://example.com/favicon.ico --json\n"),
    )
    p.add_argument("target", nargs="?", help="Page URL or direct favicon URL.")
    p.add_argument("--timeout", type=float, default=12.0, help="Request timeout (s).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.target, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
