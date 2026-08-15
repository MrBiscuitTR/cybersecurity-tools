"""Find ROP/JOP gadgets in a binary — for exploit development.

Scans a binary's executable regions for short instruction sequences ending in a
``ret`` (ROP), a register ``jmp``/``call`` (JOP), or a ``syscall``, and — crucially
for an operator building a chain — CATEGORIZES the useful ones: which gadget sets
which register, syscall gadgets, stack pivots, and memory-write primitives. So
instead of scrolling thousands of gadgets you get "pop rdi ; ret @ 0x401234"
directly, and can ``--search`` for anything specific.

Self-contained on ``capstone`` (no ropper/ROPgadget needed). x86 / x86-64 get the
full unaligned walk-back search; other arches are best-effort.

Dependencies: standard library + ``capstone``. No external API.

Safety: read-only static analysis. Reads the binary and disassembles it; never runs it.

Usage:
    python -m reversing.gadgets ./target
    python -m reversing.gadgets ./target --search "pop rdi"
    python -m reversing.gadgets ./target --all --json
    python -m reversing.gadgets blob.bin --raw --arch x86-64 --base 0x400000
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys

from common.output import emit, log

_ARCH = {  # name -> (capstone arch const name, mode const expr, is_x86)
    "x86-64": ("CS_ARCH_X86", "CS_MODE_64", True),
    "x86": ("CS_ARCH_X86", "CS_MODE_32", True),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM", False),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM", False),
    "mips": ("CS_ARCH_MIPS", "CS_MODE_32|CS_MODE_BIG_ENDIAN", False),
    "mipsel": ("CS_ARCH_MIPS", "CS_MODE_32|CS_MODE_LITTLE_ENDIAN", False),
}
_ELF_MACHINE_ARCH = {0x3e: "x86-64", 0x03: "x86", 0x28: "arm", 0xb7: "arm64", 0x08: "mips"}


# --- executable region extraction -------------------------------------------

def _elf_exec_segments(data: bytes) -> tuple[list[tuple[int, bytes]], str]:
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    machine = struct.unpack(end + "H", data[18:20])[0]
    arch = _ELF_MACHINE_ARCH.get(machine, "x86-64")
    if is64:
        e_phoff = struct.unpack(end + "Q", data[32:40])[0]
        e_phentsize, e_phnum = struct.unpack(end + "HH", data[54:58])
    else:
        e_phoff = struct.unpack(end + "I", data[28:32])[0]
        e_phentsize, e_phnum = struct.unpack(end + "HH", data[42:46])
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack(end + "I", data[off:off + 4])[0]
        if p_type != 1:  # PT_LOAD
            continue
        if is64:
            p_flags = struct.unpack(end + "I", data[off + 4:off + 8])[0]
            p_offset, p_vaddr = struct.unpack(end + "QQ", data[off + 8:off + 24])
            p_filesz = struct.unpack(end + "Q", data[off + 32:off + 40])[0]
        else:
            p_offset, p_vaddr = struct.unpack(end + "II", data[off + 4:off + 12])
            p_filesz, _p_memsz, p_flags = struct.unpack(end + "III", data[off + 16:off + 28])
        if p_flags & 0x1:  # PF_X executable
            segs.append((p_vaddr, data[p_offset:p_offset + p_filesz]))
    return segs, arch


def _pe_exec_sections(data: bytes) -> list[tuple[int, bytes]]:
    import pefile
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    out = []
    for s in pe.sections:
        if s.Characteristics & 0x20000000:  # MEM_EXECUTE
            out.append((base + s.VirtualAddress, s.get_data()))
    pe.close()
    return out


def _regions(path: str, raw: bool, arch: str, base: int) -> tuple[list[tuple[int, bytes]], str]:
    with open(path, "rb") as fh:
        data = fh.read()
    if raw:
        return [(base, data)], arch
    if data[:4] == b"\x7fELF":
        return _elf_exec_segments(data)
    if data[:2] == b"MZ":
        return _pe_exec_sections(data), arch
    return [(base, data)], arch  # unknown -> treat as raw


# --- gadget search (x86/x86-64) ---------------------------------------------

def _terminators(code: bytes) -> list[tuple[int, int]]:
    """Return (start, end) byte offsets of gadget-terminating instructions."""
    ends = []
    n = len(code)
    for i in range(n):
        b = code[i]
        if b == 0xC3:                                   # ret
            ends.append((i, i + 1))
        elif b == 0xC2 and i + 3 <= n:                  # ret imm16
            ends.append((i, i + 3))
        elif b == 0x0F and i + 1 < n and code[i + 1] == 0x05:   # syscall
            ends.append((i, i + 2))
        elif b == 0xFF and i + 1 < n and (0xE0 <= code[i + 1] <= 0xE7
                                          or 0xD0 <= code[i + 1] <= 0xD7):  # jmp/call reg
            ends.append((i, i + 2))
    return ends


_BAD_MID = re.compile(r"^(j|call|ret|loop|int)")  # control flow not allowed mid-gadget


def _find_x86(md, vaddr: int, code: bytes, max_insns: int) -> list[dict]:
    gadgets, seen = [], set()
    max_back = max_insns * 8
    for tstart, tend in _terminators(code):
        for start in range(max(0, tstart - max_back), tstart + 1):
            insns = list(md.disasm(code[start:tend], vaddr + start))
            if not insns:
                continue
            last = insns[-1]
            if last.address != vaddr + tstart:          # must land exactly on terminator
                continue
            if len(insns) > max_insns:
                continue
            bad = False
            for ins in insns[:-1]:
                if _BAD_MID.match(ins.mnemonic):
                    bad = True
                    break
            if bad:
                continue
            text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
            if text in seen:
                continue
            seen.add(text)
            gadgets.append({"address": hex(insns[0].address), "gadget": text})
    return gadgets


def _find_fixed(md, vaddr: int, code: bytes, max_insns: int) -> list[dict]:
    """Best-effort for fixed-width arches: linear disasm, cut gadgets ending at a
    return-like instruction (bx lr / pop {..,pc} / jr ra / ret)."""
    insns = list(md.disasm(code, vaddr))
    term = re.compile(r"(bx\s+lr|pop\s+\{[^}]*pc[^}]*\}|jr\s+\$?ra|\bret\b|\beret\b)")
    gadgets, seen = [], set()
    for idx, ins in enumerate(insns):
        txt = f"{ins.mnemonic} {ins.op_str}"
        if term.search(txt):
            for depth in range(1, max_insns + 1):
                start = idx - depth + 1
                if start < 0:
                    break
                seq = insns[start:idx + 1]
                text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in seq)
                if text not in seen:
                    seen.add(text)
                    gadgets.append({"address": hex(seq[0].address), "gadget": text})
    return gadgets


# --- categorization ---------------------------------------------------------

def _categorize(gadgets: list[dict]) -> dict:
    cats: dict[str, list[dict]] = {"register-control": [], "syscall": [],
                                   "stack-pivot": [], "mem-write": []}
    pivot = re.compile(r"(leave ;|xchg .*[re]sp|mov [re]sp,|add [re]sp,|pop [re]sp)")
    write = re.compile(r"mov (?:qword|dword|word|byte)? ?ptr \[[^\]]+\],")
    for g in gadgets:
        t = g["gadget"]
        if re.match(r"^pop \w+ ; ret$", t) or re.match(r"^pop \w+ ; pop \w+ ; ret$", t):
            cats["register-control"].append(g)
        if t.endswith("syscall") or "; syscall" in t or t == "syscall":
            cats["syscall"].append(g)
        if pivot.search(t):
            cats["stack-pivot"].append(g)
        if write.search(t):
            cats["mem-write"].append(g)
    return {k: v for k, v in cats.items() if v}


def run(path: str, *, raw: bool = False, arch: str = "x86-64", base: int = 0x400000,
        max_insns: int = 5, search: str = "") -> dict:
    """Find and categorize gadgets in ``path``."""
    try:
        import capstone
    except ImportError:
        raise FileNotFoundError("capstone not installed (pip install capstone)")
    if not os.path.exists(path):
        raise FileNotFoundError(f"file not found: {path}")

    regions, detected = _regions(path, raw, arch, base)
    use_arch = arch if raw else detected
    if use_arch not in _ARCH:
        use_arch = "x86-64"
    arch_c, mode_c, is_x86 = _ARCH[use_arch]
    mode = 0
    for part in mode_c.split("|"):
        mode |= getattr(capstone, part)
    md = capstone.Cs(getattr(capstone, arch_c), mode)

    log(f"[*] searching gadgets ({use_arch}) in {len(regions)} exec region(s) ...")
    all_g: list[dict] = []
    for vaddr, code in regions:
        all_g += _find_x86(md, vaddr, code, max_insns) if is_x86 \
            else _find_fixed(md, vaddr, code, max_insns)
    # Global dedup by gadget text.
    seen, gadgets = set(), []
    for g in all_g:
        if g["gadget"] not in seen:
            seen.add(g["gadget"])
            gadgets.append(g)

    result = {"file": path, "arch": use_arch, "count": len(gadgets),
              "categories": _categorize(gadgets)}
    if search:
        rx = re.compile(search, re.I)
        result["matches"] = [g for g in gadgets if rx.search(g["gadget"])]
    result["gadgets"] = gadgets  # full list (JSON / --all)
    return result


def _compact_lines(res: dict, show_all: bool) -> list[str]:
    lines = [f"# gadgets: {res['file']}  arch={res['arch']}  ({res['count']} unique)"]
    if "matches" in res:
        lines.append(f"## matches ({len(res['matches'])})")
        lines += [f"  {g['gadget']}  @ {g['address']}" for g in res["matches"]]
        return lines
    for cat, items in res["categories"].items():
        lines.append(f"## {cat} ({len(items)})")
        lines += [f"  {g['gadget']}  @ {g['address']}" for g in items[:60]]
    if show_all:
        lines.append(f"## all gadgets ({res['count']})")
        lines += [f"  {g['gadget']}  @ {g['address']}" for g in res["gadgets"]]
    else:
        lines.append("# (use --search '<regex>' to grep, or --all/--json for the full list)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.gadgets",
        description="Find & categorize ROP/JOP gadgets (capstone-based, no ropper needed).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.gadgets ./target\n"
                "  python -m reversing.gadgets ./target --search 'pop rdi'\n"
                "  python -m reversing.gadgets ./target --all --json\n"),
    )
    p.add_argument("file", nargs="?", help="Binary (ELF/PE) or raw blob (with --raw).")
    p.add_argument("--search", metavar="REGEX", help="Only show gadgets matching REGEX.")
    p.add_argument("--all", action="store_true", help="List every gadget (large).")
    p.add_argument("--max-insns", type=int, default=5, help="Max instructions per gadget (default 5).")
    p.add_argument("--raw", action="store_true", help="Treat file as raw code at --base.")
    p.add_argument("--arch", default="x86-64", help="Arch (raw/override): " + ", ".join(_ARCH))
    p.add_argument("--base", type=lambda x: int(x, 0), default=0x400000, help="Base addr for --raw.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.file:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.file, raw=args.raw, arch=args.arch, base=args.base,
                  max_insns=args.max_insns, search=args.search or "")
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res, args.all))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
