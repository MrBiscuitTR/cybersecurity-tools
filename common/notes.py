"""Persistent scratch notes — so findings survive context compaction/overflow.

An autonomous operator's context gets summarized or truncated on long engagements;
anything not written down is lost. This is a tiny append-and-read notebook the model
should use to record every finding, credential, host, and idea AS IT GOES, and to
re-read after a compaction to recover state. Cheap insurance for long hunts.

Actions:
    append  add a timestamped entry (a finding, a lead, a decision) to the notes file
    read    dump the whole notes file back (recover state after compaction)
    clear   start a fresh notes file (rarely needed)

Notes live in a single markdown file (default ./ENGAGEMENT_NOTES.md; override with
--file, e.g. put it in the target repo). It's plain text — grep/read it freely.

Dependencies: standard library only. Safety: writes only to the notes file you name.

Usage:
    python -m common.notes append "SQLi confirmed in /search?q= (union-based), see app.py:42"
    python -m common.notes read
    python -m common.notes append --file /repo/NOTES.md "creds: admin:hunter2 (from config)"
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys

DEFAULT_FILE = "ENGAGEMENT_NOTES.md"


def append(content: str, file: str = DEFAULT_FILE) -> dict:
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    new_file = not os.path.exists(file)
    with open(file, "a", encoding="utf-8") as fh:
        if new_file:
            fh.write("# Engagement notes\n\n"
                     "<!-- Append every finding/lead/decision. Brief but complete: what, where,\n"
                     "     evidence, severity, and how it chains. This file survives compaction. -->\n\n")
        fh.write(f"- **[{stamp}]** {content.strip()}\n")
    return {"action": "append", "file": file, "bytes": os.path.getsize(file)}


def read(file: str = DEFAULT_FILE) -> dict:
    if not os.path.exists(file):
        return {"action": "read", "file": file, "content": "", "exists": False}
    with open(file, encoding="utf-8", errors="replace") as fh:
        return {"action": "read", "file": file, "content": fh.read(), "exists": True}


def clear(file: str = DEFAULT_FILE) -> dict:
    # Truncate (not delete) — a destructive delete is intentionally not offered here.
    open(file, "w", encoding="utf-8").close()
    return {"action": "clear", "file": file}


def run(action: str, content: str = "", file: str = DEFAULT_FILE) -> dict:
    if action == "append":
        return append(content, file)
    if action == "read":
        return read(file)
    if action == "clear":
        return clear(file)
    raise ValueError(f"unknown action {action!r}; use append|read|clear")


def _compact_lines(res: dict) -> list[str]:
    if res["action"] == "read":
        return [f"# notes: {res['file']}"] + ([res["content"]] if res["exists"]
                                              else ["# (no notes yet)"])
    if res["action"] == "append":
        return [f"# noted -> {res['file']} ({res['bytes']} bytes)"]
    return [f"# cleared {res['file']}"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="common.notes", description="Persistent scratch notes (survive compaction).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m common.notes append \"XSS in /profile name field\"\n"
               "  python -m common.notes read\n")
    p.add_argument("action", nargs="?", choices=("append", "read", "clear"))
    p.add_argument("content", nargs="?", default="", help="Text to append.")
    p.add_argument("--file", default=DEFAULT_FILE, help="Notes file (default ENGAGEMENT_NOTES.md).")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.action or (args.action == "append" and not args.content):
        build_parser().print_help(sys.stderr)
        return 2
    from common.output import emit
    res = run(args.action, content=args.content, file=args.file)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
