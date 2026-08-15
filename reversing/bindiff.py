"""Diff two binaries function-by-function — pinpoint a security patch (1-day analysis).

Given an OLD and a NEW build of the same program (e.g. a vulnerable binary and its
patched version), this finds exactly which functions changed, added, or were removed,
and shows the instruction-level diff of each change. That changed function is almost
always the fix — reading its diff tells you what the bug was and how to trigger it.
This is the tedious core of 1-day exploit development, automated.

How it works: disassembles both with ``objdump``, matches functions by name, and
compares NORMALIZED instruction streams (absolute addresses/relocation-dependent
targets are masked, so recompilation noise doesn't create false diffs). A unified
diff is produced for every function whose real content changed.

Dependencies: standard library (``difflib``) + ``objdump`` (binutils). No API.

Safety: read-only static analysis of two files. Nothing is executed.

Usage:
    python -m reversing.bindiff ./app-1.0 ./app-1.1
    python -m reversing.bindiff old.bin new.bin --json
    python -m reversing.bindiff old new --context 2 --max-funcs 20
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys

from reversing.disasm import _disasm_objdump

# "1040 <strcmp@plt>" -> "<strcmp@plt>"; long hex addresses -> ADDR; drop comments.
_SYMREF = re.compile(r"\b[0-9a-f]+ (<[^>]+>)")
_RIP = re.compile(r"\[rip[+-]0x[0-9a-f]+\]")   # rip-relative displacements shift with layout
_ADDR = re.compile(r"\b0x[0-9a-f]{4,}\b")
_BARE = re.compile(r"\b[0-9a-f]{4,}\b")


def _normalize(text: str) -> str:
    t = text.split("#", 1)[0].strip()
    t = _SYMREF.sub(r"\1", t)          # keep the symbol, drop the shifting address
    t = _RIP.sub("[rip+OFF]", t)       # mask layout-dependent rip-relative offsets
    t = _ADDR.sub("ADDR", t)
    t = _BARE.sub("ADDR", t)           # bare code addresses (jump targets w/o symbol)
    return re.sub(r"\s+", " ", t)


def _functions(path: str) -> dict[str, list[str]]:
    """Map function name -> normalized instruction lines (code functions only)."""
    out = {}
    for f in _disasm_objdump(path, "intel"):
        if f["instructions"]:
            out[f["name"]] = [_normalize(i["text"]) for i in f["instructions"]]
    return out


def run(old: str, new: str, *, context: int = 3, max_funcs: int = 50) -> dict:
    """Diff ``old`` vs ``new``. Returns changed/added/removed function info."""
    fa, fb = _functions(old), _functions(new)
    names_a, names_b = set(fa), set(fb)

    changed = []
    for name in sorted(names_a & names_b):
        a, b = fa[name], fb[name]
        if a == b:
            continue
        ratio = difflib.SequenceMatcher(None, a, b).ratio()
        diff = list(difflib.unified_diff(a, b, lineterm="", n=context,
                                         fromfile=f"{name}(old)", tofile=f"{name}(new)"))
        added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
        changed.append({"name": name, "similarity": round(ratio, 3),
                        "added": added, "removed": removed, "diff": diff})

    # Most-changed first, but a security patch is often SMALL — the operator reads all.
    changed.sort(key=lambda c: c["similarity"])
    added_fns = sorted(names_b - names_a)
    removed_fns = sorted(names_a - names_b)
    return {
        "old": old, "new": new,
        "summary": {"matched": len(names_a & names_b), "changed": len(changed),
                    "added": len(added_fns), "removed": len(removed_fns)},
        "changed": changed[:max_funcs],
        "added_functions": added_fns,
        "removed_functions": removed_fns,
    }


def _compact_lines(res: dict) -> list[str]:
    s = res["summary"]
    lines = [f"# bindiff: {res['old']}  ->  {res['new']}",
             f"# matched={s['matched']}  changed={s['changed']}  "
             f"added={s['added']}  removed={s['removed']}"]
    if res["added_functions"]:
        lines.append("## added functions (present only in NEW)")
        lines += [f"  {n}" for n in res["added_functions"]]
    if res["removed_functions"]:
        lines.append("## removed functions (present only in OLD)")
        lines += [f"  {n}" for n in res["removed_functions"]]
    if res["changed"]:
        lines.append("## CHANGED functions (least similar first — the patch is usually here)")
        for c in res["changed"]:
            lines.append(f"### {c['name']}  similarity={c['similarity']}  "
                         f"(+{c['added']}/-{c['removed']})")
            lines += ["  " + d for d in c["diff"]]
    if not (res["changed"] or res["added_functions"] or res["removed_functions"]):
        lines.append("# no function-level differences (identical, or symbols stripped — "
                     "objdump needs names to match functions)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.bindiff",
        description="Function-level diff of two binaries (find the security patch).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.bindiff ./app-1.0 ./app-1.1\n"
                "  python -m reversing.bindiff old.bin new.bin --json\n"),
    )
    p.add_argument("old", nargs="?", help="Old/vulnerable binary.")
    p.add_argument("new", nargs="?", help="New/patched binary.")
    p.add_argument("--context", type=int, default=3, help="Diff context lines (default 3).")
    p.add_argument("--max-funcs", type=int, default=50, help="Max changed funcs to show.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.old or not args.new:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.old, args.new, context=args.context, max_funcs=args.max_funcs)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    from common.output import emit
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
