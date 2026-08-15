import ast

import pytest

from reversing import pwn_template as pt

_BASE = {"file": "x", "arch": "amd64", "bits": 64, "pie": False, "nx": True,
         "relro": "partial", "static": False, "canary": False, "win_func": None,
         "has_system": False, "has_binsh": False, "dangerous_inputs": ["read"]}


def _info(**over):
    return {**_BASE, **over}


@pytest.mark.parametrize("info,expected", [
    (_info(win_func="win"), "ret2win"),
    (_info(has_system=True, has_binsh=True), "ret2system"),
    (_info(nx=False), "shellcode"),
    (_info(nx=True, static=False), "ret2libc"),
    (_info(nx=True, static=True), "rop-generic"),
])
def test_strategy_generates_valid_python(info, expected):
    # analyze() picks strategy from protections; emulate its decision then generate.
    if info["win_func"]:
        strat = "ret2win"
    elif info["has_system"] and info["has_binsh"]:
        strat = "ret2system"
    elif not info["nx"]:
        strat = "shellcode"
    elif not info["static"]:
        strat = "ret2libc"
    else:
        strat = "rop-generic"
    assert strat == expected
    script = pt.generate_script({**info, "strategy": strat})
    ast.parse(script)                      # generated exploit must be valid Python
    assert "from pwn import *" in script
    if strat == "ret2win":
        assert info["win_func"] in script


def test_canary_and_pie_notes():
    script = pt.generate_script(_info(win_func="win", canary=True, pie=True, strategy="ret2win"))
    assert "canary" in script.lower() and "PIE" in script
    ast.parse(script)


def test_analyze_rejects_non_elf(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"MZ not an elf")
    with pytest.raises(ValueError):
        pt.analyze(str(p))


def test_main_no_args_returns_2(capsys):
    assert pt.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()
