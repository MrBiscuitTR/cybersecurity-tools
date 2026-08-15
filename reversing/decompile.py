"""Decompile a binary to pseudo-C with Ghidra headless — output built for an LLM.

Ghidra is a GUI tool, but its ``analyzeHeadless`` runner drives the same analysis
and decompiler from the command line. This wraps it: it imports the binary, runs
auto-analysis, and (via a bundled Ghidra script) dumps a compact FUNCTION MAP or
the DECOMPILED PSEUDO-C for a chosen function — the form an LLM reasons over best,
whether the binary is stripped, optimized, or obfuscated.

Three modes:
  list (default)      imports + function table + defined strings — the small map;
                      start here to pick a target without dumping the whole binary
  --function NAME     decompile functions whose name or entry address matches NAME
  --all               decompile every function (can be large — mind the context)

Requires Ghidra on the host (``analyzeHeadless``). This is meant to run where
Ghidra lives (e.g. the Kali box). Set GHIDRA_HEADLESS to point at the binary if it
isn't on PATH or at the common locations.

Dependencies: standard library. Wraps the external ``analyzeHeadless`` (read-only:
Ghidra imports a COPY into a scratch project which is deleted afterward; the target
binary is never modified and never executed).

Usage:
    python -m reversing.decompile ./sample                 # function map
    python -m reversing.decompile ./sample --function main # pseudo-C for main
    python -m reversing.decompile ./sample --all --json
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile

from common import proc
from common.output import emit as emit_out
from common.output import log

# Java GhidraScript (compiled on the fly by Ghidra). Java is used instead of a
# .py script because modern Ghidra needs PyGhidra for Python, which isn't enabled
# in headless by default; Java scripts always work.
_SCRIPT = "ghidra_decompile.java"
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_HEADLESS_CANDIDATES = [
    os.environ.get("GHIDRA_HEADLESS", ""),
    "analyzeHeadless",
    "/usr/share/ghidra/support/analyzeHeadless",
    "/opt/ghidra/support/analyzeHeadless",
    "/opt/ghidra/ghidra/support/analyzeHeadless",
]


def _find_headless() -> str | None:
    for c in _HEADLESS_CANDIDATES:
        if c and (proc.have(c) or os.path.exists(c)):
            return c
    return None


def _run_headless(binary: str, script_args: list[str], timeout: float) -> str:
    """Run analyzeHeadless with the bundled post-script; return its stdout."""
    headless = _find_headless()
    if not headless:
        raise FileNotFoundError(
            "analyzeHeadless not found. Install Ghidra or set GHIDRA_HEADLESS. "
            "(Kali: apt install ghidra -> /usr/share/ghidra/support/analyzeHeadless)")
    if not os.path.exists(binary):
        raise FileNotFoundError(f"binary not found: {binary}")
    proj = tempfile.mkdtemp(prefix="ghidra_")
    argv = [headless, proj, "triage",
            "-import", binary,
            "-scriptPath", _SCRIPT_DIR,
            "-postScript", _SCRIPT] + script_args + ["-deleteProject"]
    log(f"[*] ghidra analyzing {binary} (this takes a while) ...")
    ran = proc.run(argv, timeout=timeout)
    if not ran.found:
        raise FileNotFoundError(ran.stderr)
    # Ghidra logs to stderr; our markers are on stdout. Fall back to stderr if needed.
    return ran.stdout if "@@@BEGIN@@@" in ran.stdout else ran.stdout + "\n" + ran.stderr


def _slice(output: str) -> str:
    """Return only the text between our BEGIN/END markers (drop Ghidra log noise)."""
    b = output.find("@@@BEGIN@@@")
    e = output.find("@@@END@@@")
    if b == -1:
        return ""
    return output[b:e if e != -1 else len(output)]


def _parse_list(output: str) -> dict:
    body = _slice(output)
    section, imports, functions, strings = None, [], [], []
    for line in body.splitlines():
        if line.startswith("@@@IMPORTS@@@"):
            section = "imports"; continue
        if line.startswith("@@@FUNCTIONS@@@"):
            section = "functions"; continue
        if line.startswith("@@@STRINGS@@@"):
            section = "strings"; continue
        if line.startswith("@@@BEGIN@@@") or not line.strip():
            continue
        val = line.strip()
        if section == "imports":
            imports.append(val)
        elif section == "functions":
            functions.append(val)
        elif section == "strings":
            strings.append(val)
    return {"imports": imports, "functions": functions, "strings": strings}


def _parse_funcs(output: str) -> list[dict]:
    body = _slice(output)
    funcs, cur = [], None
    for line in body.splitlines():
        m = re.match(r"@@@FUNC@@@ (.*) @ (\S+)$", line)
        if m:
            cur = {"name": m.group(1), "address": m.group(2), "code": []}
            funcs.append(cur)
        elif cur is not None and not line.startswith("@@@"):
            # Drop stray Ghidra log lines that can interleave on stdout.
            if re.match(r"(WARN|INFO|ERROR|DEBUG)\s", line):
                continue
            cur["code"].append(line)
    for f in funcs:
        f["code"] = "\n".join(f["code"]).strip()
    return funcs


def run(binary: str, *, mode: str = "list", target: str = "", timeout: float = 600.0) -> dict:
    """Decompile/inspect ``binary``.

    mode: "list" (map), "func" (needs target), or "all". Returns:
      list -> {file, mode, imports, functions, strings}
      func/all -> {file, mode, functions: [{name, address, code}]}
    """
    if mode == "func":
        script_args = ["func", target]
    elif mode == "all":
        script_args = ["all"]
    else:
        script_args = ["list"]
    out = _run_headless(binary, script_args, timeout)
    if mode == "list":
        return {"file": binary, "mode": mode, **_parse_list(out)}
    return {"file": binary, "mode": mode, "functions": _parse_funcs(out)}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# decompile: {res['file']}  (mode={res['mode']})"]
    if res["mode"] == "list":
        if res.get("imports"):
            lines.append(f"## imports ({len(res['imports'])})")
            lines += [f"  {i}" for i in res["imports"]]
        lines.append(f"## functions ({len(res.get('functions', []))})")
        lines += [f"  {f}" for f in res.get("functions", [])]
        if res.get("strings"):
            lines.append(f"## strings ({len(res['strings'])})")
            lines += [f"  {s}" for s in res["strings"]]
        if not res.get("functions"):
            lines.append("# (no functions — analysis may have failed; check Ghidra is installed)")
    else:
        if not res["functions"]:
            lines.append("# no matching functions decompiled")
        for f in res["functions"]:
            lines.append(f"## {f['name']} @ {f['address']}")
            lines.append(f["code"])
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.decompile",
        description="Decompile a binary to pseudo-C via Ghidra headless.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.decompile ./sample\n"
                "  python -m reversing.decompile ./sample --function main\n"
                "  python -m reversing.decompile ./sample --all --json\n"),
    )
    p.add_argument("binary", nargs="?", help="Path to the binary to analyze.")
    p.add_argument("--function", metavar="NAME", help="Decompile functions matching NAME/address.")
    p.add_argument("--all", action="store_true", help="Decompile every function (large).")
    p.add_argument("--timeout", type=float, default=600.0, help="Max seconds for Ghidra (default 600).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.binary:
        build_parser().print_help(sys.stderr)
        return 2
    mode = "func" if args.function else "all" if args.all else "list"
    try:
        res = run(args.binary, mode=mode, target=args.function or "", timeout=args.timeout)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit_out(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
