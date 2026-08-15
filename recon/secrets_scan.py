"""Scan a file or directory tree for leaked secrets (gitleaks-style).

Walks a path and greps every text file for credentials — API keys, tokens,
private keys, and generic secret assignments — reporting each as file:line so an
operator can jump straight to it. Reuses the same high-signal pattern set as the
JavaScript miner, so web bundles and source trees are covered by one ruleset.

Dependencies: standard library only. No external API. Reads local files.

Safety: read-only. Never modifies files. Any secret reported is REAL — treat the
output as sensitive and never commit it.

Usage:
    python -m recon.secrets_scan ./src
    python -m recon.secrets_scan config.js --json
    python -m recon.secrets_scan . --max-size 2000000
"""

from __future__ import annotations

import argparse
import os
import sys

from common.output import emit, log
from web.js_recon import _SECRET_PATTERNS  # single source of truth for the ruleset

# Directories and file types not worth scanning (noise / binaries).
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".idea", ".mypy_cache", ".pytest_cache", "vendor"}
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip",
             ".gz", ".tar", ".7z", ".exe", ".dll", ".so", ".dylib", ".class",
             ".jar", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".pyc", ".o"}


def _iter_files(path: str, max_size: int):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if os.path.splitext(name)[1].lower() in _SKIP_EXT:
                continue
            fp = os.path.join(root, name)
            try:
                if os.path.getsize(fp) <= max_size:
                    yield fp
            except OSError:
                continue


def _redact(value: str) -> str:
    """Keep the ends, mask the middle so the report is useful but not a full leak."""
    if len(value) <= 12:
        return value[:3] + "…"
    return f"{value[:6]}…{value[-4:]}"


def run(path: str, *, max_size: int = 1_000_000) -> dict:
    """Scan ``path`` (file or dir) for secrets. Returns findings with file:line."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"path not found: {path}")
    findings: list[dict] = []
    scanned = 0
    for fp in _iter_files(path, max_size):
        scanned += 1
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    if len(line) > 4000:      # skip minified megalines for the line view
                        line = line[:4000]
                    for label, rx in _SECRET_PATTERNS:
                        m = rx.search(line)
                        if m:
                            val = m.group(0)
                            findings.append({
                                "type": label, "file": os.path.relpath(fp, path)
                                if os.path.isdir(path) else fp,
                                "line": lineno, "match": _redact(val),
                            })
        except OSError:
            continue
        if scanned % 500 == 0:
            log(f"[*] scanned {scanned} files ...")
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    return {"path": path, "files_scanned": scanned,
            "count": len(findings), "by_type": by_type, "findings": findings}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# secrets_scan: {res['path']}  "
             f"({res['files_scanned']} files, {res['count']} findings)"]
    if res["by_type"]:
        lines.append("# by type: " + ", ".join(f"{k}={v}" for k, v in sorted(res["by_type"].items())))
    if res["findings"]:
        lines.append("## SECRETS (verify; handle as sensitive)")
        lines += [f"[{f['type']}] {f['file']}:{f['line']}  {f['match']}" for f in res["findings"]]
    else:
        lines.append("# no secrets matched")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.secrets_scan",
        description="Scan a file/directory for leaked secrets (API keys, tokens, private keys).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m recon.secrets_scan ./src\n"
                "  python -m recon.secrets_scan config.js --json\n"),
    )
    p.add_argument("path", nargs="?", help="File or directory to scan.")
    p.add_argument("--max-size", type=int, default=1_000_000,
                   help="Skip files larger than this many bytes (default 1MB).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.path:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.path, max_size=args.max_size)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
