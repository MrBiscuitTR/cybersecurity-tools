"""Disassemble a binary (or a raw code blob) to annotated assembly.

Complements the decompiler: when the pseudo-C looks wrong or you need to see the
actual instructions (a specific gadget, an anti-debug trick, exact syscall setup),
this gives you the assembly — per function for real binaries (via ``objdump``), or
for a flat blob of bytes (shellcode, an extracted code region) via ``capstone``.

Modes:
  list (default)   function table (name @ address) parsed from objdump
  --function NAME   disassemble the function(s) matching NAME/address
  --all             disassemble every function
  --raw --arch A    treat the file as raw machine code and disassemble with capstone
                    (arch: x86-64, x86, arm, arm64, mips, mipsel); --base sets the
                    start address, --offset skips leading bytes

Dependencies: standard library + ``objdump`` (binutils, universal) for real binaries;
``capstone`` (pip) only for --raw. No external API.

Safety: read-only. Disassembles bytes; never executes anything.

Usage:
    python -m reversing.disasm ./sample
    python -m reversing.disasm ./sample --function main --syntax intel
    python -m reversing.disasm shellcode.bin --raw --arch x86-64 --base 0x1000
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from common import proc
from common.output import emit, log

_LABEL = re.compile(r"^([0-9a-fA-F]+)\s+<([^>]+)>:")
_INSN = re.compile(r"^\s*([0-9a-fA-F]+):\t([0-9a-fA-F ]+?)\t+(.*)$")

# capstone arch/mode selectors for --raw.
_CAPSTONE = {
    "x86-64": ("CS_ARCH_X86", "CS_MODE_64"),
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "thumb": ("CS_ARCH_ARM", "CS_MODE_THUMB"),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "mips": ("CS_ARCH_MIPS", "CS_MODE_32|CS_MODE_BIG_ENDIAN"),
    "mipsel": ("CS_ARCH_MIPS", "CS_MODE_32|CS_MODE_LITTLE_ENDIAN"),
}


def _objdump() -> str | None:
    for c in ("objdump", "/usr/bin/objdump"):
        if proc.have(c) or os.path.exists(c):
            return c
    return None


def _disasm_objdump(path: str, syntax: str) -> list[dict]:
    """Parse objdump -d into a list of {name, address, instructions:[{addr,bytes,text}]}."""
    od = _objdump()
    if not od:
        raise FileNotFoundError("objdump not found (install binutils).")
    ran = proc.run([od, "-d", "-M", syntax, path], timeout=180)
    if not ran.found:
        raise FileNotFoundError(ran.stderr)
    if ran.code != 0 and not ran.stdout:
        raise ValueError(ran.stderr.strip() or "objdump failed")
    funcs, cur = [], None
    for line in ran.stdout.splitlines():
        ml = _LABEL.match(line)
        if ml:
            cur = {"name": ml.group(2), "address": ml.group(1), "instructions": []}
            funcs.append(cur)
            continue
        mi = _INSN.match(line)
        if mi and cur is not None:
            cur["instructions"].append({"addr": mi.group(1),
                                        "bytes": mi.group(2).strip(),
                                        "text": mi.group(3).strip()})
    return funcs


def _disasm_raw(path: str, arch: str, base: int, offset: int) -> list[dict]:
    try:
        import capstone
    except ImportError:
        raise FileNotFoundError("capstone not installed (pip install capstone) — needed for --raw")
    if arch not in _CAPSTONE:
        raise ValueError(f"unknown arch {arch!r}; choose from {', '.join(_CAPSTONE)}")
    arch_c, mode_c = _CAPSTONE[arch]
    mode = 0
    for part in mode_c.split("|"):
        mode |= getattr(capstone, part)
    md = capstone.Cs(getattr(capstone, arch_c), mode)
    with open(path, "rb") as fh:
        code = fh.read()[offset:]
    insns = [{"addr": f"{i.address:x}", "bytes": i.bytes.hex(),
              "text": f"{i.mnemonic} {i.op_str}".strip()}
             for i in md.disasm(code, base)]
    return [{"name": f"raw@{arch}", "address": f"{base:x}", "instructions": insns}]


def run(path: str, *, mode: str = "list", target: str = "", syntax: str = "intel",
        raw: bool = False, arch: str = "x86-64", base: int = 0x1000,
        offset: int = 0) -> dict:
    """Disassemble ``path``. See module docstring for modes/args."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"file not found: {path}")
    if raw:
        log(f"[*] capstone raw disasm ({arch}) ...")
        funcs = _disasm_raw(path, arch, base, offset)
        return {"file": path, "mode": "raw", "arch": arch, "functions": funcs}

    all_funcs = _disasm_objdump(path, syntax)
    # Keep only functions that actually have instructions (drop PLT stubs w/o body).
    code_funcs = [f for f in all_funcs if f["instructions"]]
    if mode == "list":
        return {"file": path, "mode": "list",
                "functions": [{"name": f["name"], "address": f["address"],
                               "instructions": len(f["instructions"])} for f in code_funcs]}
    if mode == "func" and target:
        exact = [f for f in code_funcs if f["name"] == target or f["address"] == target]
        sel = exact or [f for f in code_funcs if target in f["name"]]
    else:  # all
        sel = code_funcs
    return {"file": path, "mode": mode, "functions": sel}


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# disasm: {res['file']}  (mode={res['mode']}"
             + (f", arch={res['arch']}" if res.get("arch") else "") + ")"]
    if res["mode"] == "list":
        lines.append(f"## functions ({len(res['functions'])})")
        lines += [f"  {f['name']} @ {f['address']}  ({f['instructions']} insns)"
                  for f in res["functions"]]
        return lines
    if not res["functions"]:
        lines.append("# no matching functions")
    for f in res["functions"]:
        lines.append(f"## {f['name']} @ {f['address']}")
        lines += [f"  {i['addr']}:  {i['text']}" for i in f["instructions"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.disasm",
        description="Annotated disassembly (objdump) + raw-blob disassembly (capstone).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.disasm ./sample\n"
                "  python -m reversing.disasm ./sample --function main\n"
                "  python -m reversing.disasm sc.bin --raw --arch x86-64 --base 0x1000\n"),
    )
    p.add_argument("file", nargs="?", help="Binary or raw code blob.")
    p.add_argument("--function", metavar="NAME", help="Disassemble functions matching NAME/address.")
    p.add_argument("--all", action="store_true", help="Disassemble every function.")
    p.add_argument("--syntax", choices=("intel", "att"), default="intel", help="objdump syntax.")
    p.add_argument("--raw", action="store_true", help="Treat file as raw machine code (capstone).")
    p.add_argument("--arch", default="x86-64", help="Arch for --raw: " + ", ".join(_CAPSTONE))
    p.add_argument("--base", type=lambda x: int(x, 0), default=0x1000, help="Base address for --raw.")
    p.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="Byte offset to start --raw.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.file:
        build_parser().print_help(sys.stderr)
        return 2
    mode = "func" if args.function else "all" if args.all else "list"
    try:
        res = run(args.file, mode=mode, target=args.function or "", syntax=args.syntax,
                  raw=args.raw, arch=args.arch, base=args.base, offset=args.offset)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
