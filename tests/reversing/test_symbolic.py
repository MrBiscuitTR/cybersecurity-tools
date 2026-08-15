from reversing import symbolic


def test_as_address():
    assert symbolic._as_address("0x401337") == 0x401337
    assert symbolic._as_address("4199223") == 4199223
    assert symbolic._as_address("Correct") is None


def test_compact_lines_solved():
    res = {"file": "cm", "solved": True, "mode": "stdin", "steps": 12,
           "reason": "target reached", "input": "opensesame", "input_hex": "6f70..."}
    lines = symbolic._compact_lines(res)
    assert any("SOLVED" in ln for ln in lines)
    assert any("opensesame" in ln for ln in lines)
    assert any("stdin" in ln for ln in lines)


def test_compact_lines_unsolved():
    res = {"file": "cm", "solved": False, "mode": "argv", "steps": 300,
           "reason": "target not reached within step budget", "input": "", "input_hex": ""}
    lines = symbolic._compact_lines(res)
    assert any("not solved" in ln for ln in lines)


def test_main_missing_args_returns_2(capsys):
    assert symbolic.main([]) == 2                       # no binary/find
    assert symbolic.main(["./x"]) == 2                  # missing --find
