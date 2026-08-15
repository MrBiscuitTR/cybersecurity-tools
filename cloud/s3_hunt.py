"""Hunt for cloud storage buckets (S3 / GCS / Azure Blob) and flag public ones.

From a keyword (company/product/domain), it generates candidate bucket names with
the usual permutations and checks each across AWS S3, Google Cloud Storage, and
Azure Blob — reporting which exist, which are publicly LISTABLE (the jackpot), and
which merely exist-but-private. Exposed buckets are a perennial source of breaches;
this finds them fast. You can also check one exact bucket with --bucket.

Dependencies: standard library only (anonymous HTTP checks). No API key needed.

Safety: read-only. Sends anonymous GET/list requests to public cloud endpoints; it
never writes or downloads bucket contents. Only assess assets you're authorized to.

Usage:
    python -m cloud.s3_hunt acmecorp
    python -m cloud.s3_hunt acmecorp --json
    python -m cloud.s3_hunt --bucket flaws.cloud
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys

from common import http
from common.output import emit, log

# Permutation suffixes/prefixes commonly seen in real bucket names.
_AFFIXES = ["", "backup", "backups", "dev", "development", "prod", "production",
            "staging", "test", "assets", "static", "media", "data", "files",
            "logs", "db", "database", "admin", "www", "web", "uploads", "upload",
            "public", "private", "internal", "s3", "cdn", "images", "img", "docs",
            "archive", "old", "temp", "config", "secret", "secrets"]


def _candidates(keyword: str) -> list[str]:
    kw = keyword.strip().lower().replace(" ", "-")
    names = {kw}
    for a in _AFFIXES:
        if not a:
            continue
        names |= {f"{kw}-{a}", f"{a}-{kw}", f"{kw}.{a}", f"{kw}{a}"}
    return sorted(names)


def _check_bucket(name: str, timeout: float) -> dict | None:
    """Check a bucket name across providers. Returns a hit dict or None."""
    providers = {
        "s3": f"https://{name}.s3.amazonaws.com/",
        "gcs": f"https://storage.googleapis.com/{name}/",
        "azure": f"https://{name}.blob.core.windows.net/?comp=list&restype=container",
    }
    for provider, url in providers.items():
        # Dotted names break S3 virtual-host TLS (cert), so use plain HTTP virtual-host
        # (path-style hits region-redirects). Virtual-host resolves the region for us.
        if provider == "s3" and "." in name:
            url = f"http://{name}.s3.amazonaws.com/"
        r = http.get(url, timeout=timeout, retries=0)
        body = r.body[:400]
        if provider == "s3":
            if r.status == 200 and b"<ListBucketResult" in body:
                return {"bucket": name, "provider": provider, "state": "PUBLIC-LISTABLE", "url": url}
            if r.status == 403 or b"AccessDenied" in body:
                return {"bucket": name, "provider": provider, "state": "exists-private", "url": url}
        elif provider == "gcs":
            if r.status == 200:
                return {"bucket": name, "provider": provider, "state": "PUBLIC-LISTABLE", "url": url}
            if r.status == 403:
                return {"bucket": name, "provider": provider, "state": "exists-private", "url": url}
        elif provider == "azure":
            if r.status == 200 and b"EnumerationResults" in body:
                return {"bucket": name, "provider": provider, "state": "PUBLIC-LISTABLE", "url": url}
            if r.status in (403, 409):
                return {"bucket": name, "provider": provider, "state": "exists-private", "url": url}
    return None


def run(keyword: str = "", *, bucket: str = "", timeout: float = 8.0,
        workers: int = 30) -> dict:
    """Hunt buckets for ``keyword`` (permutations) or check one exact ``bucket``."""
    names = [bucket] if bucket else _candidates(keyword)
    log(f"[*] checking {len(names)} bucket names across S3/GCS/Azure ...")
    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(names))) as pool:
        for res in pool.map(lambda n: _check_bucket(n, timeout), names):
            if res:
                hits.append(res)
    hits.sort(key=lambda h: (h["state"] != "PUBLIC-LISTABLE", h["bucket"]))
    return {"keyword": keyword or bucket, "checked": len(names), "hits": hits,
            "public": [h for h in hits if h["state"] == "PUBLIC-LISTABLE"]}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# s3_hunt: {res['keyword']}  ({res['checked']} names checked, "
             f"{len(res['hits'])} exist, {len(res['public'])} PUBLIC)"]
    if res["hits"]:
        for h in res["hits"]:
            mark = "[!] " if h["state"] == "PUBLIC-LISTABLE" else "    "
            lines.append(f"{mark}[{h['provider']}] {h['bucket']}  {h['state']}  {h['url']}")
    else:
        lines.append("# no buckets found for these permutations")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud.s3_hunt", description="Find public S3/GCS/Azure buckets from a keyword.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m cloud.s3_hunt acmecorp\n  python -m cloud.s3_hunt --bucket flaws.cloud\n")
    p.add_argument("keyword", nargs="?", help="Company/product/domain keyword to permute.")
    p.add_argument("--bucket", default="", help="Check one exact bucket name instead.")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.keyword and not args.bucket:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.keyword or "", bucket=args.bucket, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
