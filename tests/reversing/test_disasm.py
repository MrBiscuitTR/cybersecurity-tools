import pytest

from common import proc
from reversing import disasm

OBJDUMP_OUT = """\

sample:     file format elf64-x86-64

Disassembly of section .text:

0000000000001149 <check>:
    1149:\t55                   \tpush   rbp
    114a:\t48 89 e5             \tmov    rbp,rsp
    1171:\te8 ca fe ff ff       \tcall   1040 <strcmp@plt>

0000000000001180 <main>:
    1180:\t55                   \tpush   rbp
"""


def _fake_ran(stdout):
    return proc.Ran(["objdump"], 0, stdout, "", True)


def test_objdump_parse(monkeypatch):
    monkeypatch.setattr(disasm.proc, "run", lambda *a, **k: _fake_ran(OBJDUMP_OUT))
    monkeypatch.setattr(disasm, "_objdump", lambda: "objdump")
    funcs = disasm._disasm_objdump("x", "intel")
    names = [f["name"] for f in funcs]
    assert names == ["check", "main"]
    check = funcs[0]
    assert check["address"] == "0000000000001149"
    assert check["instructions"][0]["text"] == "push   rbp"
    assert any("strcmp" in i["text"] for i in check["instructions"])


def test_run_list_mode(monkeypatch):
    monkeypatch.setattr(disasm.proc, "run", lambda *a, **k: _fake_ran(OBJDUMP_OUT))
    monkeypatch.setattr(disasm, "_objdump", lambda: "objdump")
    monkeypatch.setattr(disasm.os.path, "exists", lambda p: True)
    res = disasm.run("x", mode="list")
    assert res["mode"] == "list"
    assert {"name": "check", "address": "0000000000001149", "instructions": 3} in res["functions"]


def test_run_func_exact(monkeypatch):
    monkeypatch.setattr(disasm.proc, "run", lambda *a, **k: _fake_ran(OBJDUMP_OUT))
    monkeypatch.setattr(disasm, "_objdump", lambda: "objdump")
    monkeypatch.setattr(disasm.os.path, "exists", lambda p: True)
    res = disasm.run("x", mode="func", target="main")
    assert [f["name"] for f in res["functions"]] == ["main"]


def test_compact_lines():
    res = {"file": "x", "mode": "func", "functions": [
        {"name": "check", "address": "1149",
         "instructions": [{"addr": "1149", "bytes": "55", "text": "push rbp"}]}]}
    lines = disasm._compact_lines(res)
    assert any("## check @ 1149" in ln for ln in lines)
    assert any("push rbp" in ln for ln in lines)


def test_main_no_args_returns_2(capsys):
    assert disasm.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_main_missing_file_returns_1(capsys):
    assert disasm.main(["/no/such/file"]) == 1
