"""Solve for program input with symbolic execution (angr).

Answers the question "what input makes this binary do X?" — reach a target address
or print a success string, while avoiding a failure path. It explores the program
with a symbolic input and, when it finds the target, solves for the concrete bytes.
This crushes crackmes, licence checks, and "find the flag" challenges, and finds
inputs that reach a suspicious code path in a sample — the kind of tedious search
an LLM should offload to a solver.

Input is delivered as symbolic STDIN (default) or a symbolic ARGV[1] (--argv).
The target/avoid can be an ADDRESS (0x...) or a STRING to match in stdout.

Dependencies: ``angr`` (pip). Heavy but self-contained. No external API.

Safety: angr executes the target inside its own emulated/symbolic environment
(it does not run the binary natively on the host). Still, only analyze binaries
you're authorized to. Read-only w.r.t. the file.

Usage:
    python -m reversing.symbolic ./crackme --argv --find "Correct"
    python -m reversing.symbolic ./crackme --find 0x401337 --avoid "denied"
    python -m reversing.symbolic ./bin --find "flag{" --input-size 40 --json
"""

from __future__ import annotations

import argparse
import sys

from common.output import emit, log


def _as_address(s: str):
    s = s.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def run(path: str, *, find: str, avoid: str = "", argv: bool = False,
        input_size: int = 32, max_steps: int = 300, printable: bool = True) -> dict:
    """Symbolically explore ``path`` to find input reaching ``find``.

    find/avoid: an address ("0x401337") or a string to match in stdout ("Correct").
    argv: deliver input as argv[1] instead of stdin. input_size: symbolic input length.
    Returns {solved, input, input_hex, mode, steps, reason}.
    """
    try:
        import angr
        import claripy
    except ImportError:
        raise FileNotFoundError("angr not installed (pip install angr)")
    import logging
    for noisy in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    if not (find_addr := _as_address(find)) and not find:
        raise ValueError("--find is required (an address or a stdout string)")

    log(f"[*] loading {path} with angr ...")
    proj = angr.Project(path, auto_load_libs=False)

    sym = claripy.BVS("input", 8 * input_size)
    if argv:
        state = proj.factory.full_init_state(args=[path, sym])
    else:
        state = proj.factory.full_init_state(args=[path], stdin=sym)
    if printable:  # constrain to printable ASCII -> readable, faster solving
        for i in range(input_size):
            byte = sym.get_byte(i)
            state.solver.add(claripy.Or(byte == 0, claripy.And(byte >= 0x20, byte <= 0x7e)))

    avoid_addr = _as_address(avoid) if avoid else None

    def hits(state, needle):
        try:
            return needle.encode() in state.posix.dumps(1)
        except Exception:
            return False

    find_pred = (find_addr if find_addr is not None
                 else (lambda s: hits(s, find)))
    avoid_pred = (avoid_addr if avoid_addr is not None
                  else ((lambda s: hits(s, avoid)) if avoid else None))

    simgr = proj.factory.simulation_manager(state)
    log("[*] exploring ...")

    # Bound exploration with a step budget (explore() creates the 'found' stash).
    class _Budget:
        n = 0

    def step_func(sm):
        _Budget.n += 1
        if _Budget.n >= max_steps:
            sm.move(from_stash="active", to_stash="pruned")
        return sm

    simgr.explore(find=find_pred, avoid=avoid_pred, num_find=1, step_func=step_func)
    steps = _Budget.n

    if not simgr.found:
        return {"file": path, "solved": False, "mode": "argv" if argv else "stdin",
                "steps": steps, "reason": "target not reached within step budget",
                "input": "", "input_hex": ""}

    found = simgr.found[0]
    raw = found.solver.eval(sym, cast_to=bytes)
    raw = raw.rstrip(b"\x00") or raw
    return {
        "file": path, "solved": True, "mode": "argv" if argv else "stdin",
        "steps": steps, "reason": "target reached",
        "input": raw.decode("latin-1"),
        "input_hex": raw.hex(),
    }


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# symbolic: {res['file']}  (mode={res['mode']}, steps={res['steps']})"]
    if res["solved"]:
        lines.append(f"# SOLVED — input that reaches the target:")
        lines.append(f"  ascii: {res['input']!r}")
        lines.append(f"  hex:   {res['input_hex']}")
        lines.append(f"# deliver via {'argv[1]' if res['mode'] == 'argv' else 'stdin'}")
    else:
        lines.append(f"# not solved: {res['reason']} (try a larger --input-size or --max-steps)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.symbolic",
        description="Solve for program input with symbolic execution (angr).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.symbolic ./crackme --argv --find 'Correct'\n"
                "  python -m reversing.symbolic ./crackme --find 0x401337 --avoid 'denied'\n"),
    )
    p.add_argument("binary", nargs="?", help="Binary to analyze.")
    p.add_argument("--find", help="Target: an address (0x...) or a string to see in stdout.")
    p.add_argument("--avoid", default="", help="Avoid: an address or a stdout string.")
    p.add_argument("--argv", action="store_true", help="Deliver input as argv[1] (default: stdin).")
    p.add_argument("--input-size", type=int, default=32, help="Symbolic input length (default 32).")
    p.add_argument("--max-steps", type=int, default=300, help="Exploration step budget (default 300).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.binary or not args.find:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.binary, find=args.find, avoid=args.avoid, argv=args.argv,
                  input_size=args.input_size, max_steps=args.max_steps)
    except (FileNotFoundError, ValueError, Exception) as exc:
        # angr raises many exotic exceptions; surface them cleanly rather than crash.
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
