from reversing import gadgets


def test_terminators_detects_endings():
    # ret(0xc3), ret imm16(0xc2 xx xx), syscall(0f 05), jmp reg(ff e7)
    code = b"\x90\xc3" + b"\xc2\x08\x00" + b"\x0f\x05" + b"\xff\xe7"
    ends = dict(gadgets._terminators(code))
    assert 1 in ends and ends[1] == 2          # ret at offset 1
    assert 2 in ends and ends[2] == 5          # ret imm16
    assert 5 in ends and ends[5] == 7          # syscall
    assert 7 in ends and ends[7] == 9          # jmp reg


def test_categorize():
    g = [
        {"address": "0x1", "gadget": "pop rdi ; ret"},
        {"address": "0x2", "gadget": "pop rsi ; pop r15 ; ret"},
        {"address": "0x3", "gadget": "syscall"},
        {"address": "0x4", "gadget": "leave ; ret"},
        {"address": "0x5", "gadget": "mov qword ptr [rax], rbx ; ret"},
        {"address": "0x6", "gadget": "add eax, 1 ; ret"},
    ]
    cats = gadgets._categorize(g)
    assert any("pop rdi" in x["gadget"] for x in cats["register-control"])
    assert cats["syscall"] and cats["stack-pivot"] and cats["mem-write"]


def test_elf_machine_arch_map():
    assert gadgets._ELF_MACHINE_ARCH[0x3e] == "x86-64"
    assert gadgets._ELF_MACHINE_ARCH[0xb7] == "arm64"


def test_compact_lines_search():
    res = {"file": "x", "arch": "x86-64", "count": 2,
           "matches": [{"address": "0x1", "gadget": "pop rdi ; ret"}]}
    lines = gadgets._compact_lines(res, show_all=False)
    assert any("pop rdi ; ret" in ln and "0x1" in ln for ln in lines)


def test_main_no_args_returns_2(capsys):
    assert gadgets.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()
