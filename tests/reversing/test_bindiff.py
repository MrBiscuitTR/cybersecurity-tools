from reversing import bindiff


def test_normalize_masks_layout_noise():
    assert bindiff._normalize("call   1040 <strcmp@plt>") == "call <strcmp@plt>"
    assert bindiff._normalize("lea    rdi,[rip+0xf4]        # comment") == "lea rdi,[rip+OFF]"
    assert bindiff._normalize("jmp    0x401556") == "jmp ADDR"
    assert bindiff._normalize("mov    edx,0x3f") == "mov edx,0x3f"   # small immediate kept


def test_run_detects_changed_added_removed(monkeypatch):
    old = {"main": ["mov eax,0", "ret"], "copy": ["call <strcpy>", "ret"], "gone": ["ret"]}
    new = {"main": ["mov eax,0", "ret"], "copy": ["call <strncpy>", "ret"], "fresh": ["ret"]}
    monkeypatch.setattr(bindiff, "_functions", lambda p: old if p == "a" else new)
    res = bindiff.run("a", "b")
    assert res["summary"]["changed"] == 1
    assert res["changed"][0]["name"] == "copy"
    assert res["added_functions"] == ["fresh"]
    assert res["removed_functions"] == ["gone"]
    assert any("strncpy" in d for d in res["changed"][0]["diff"])


def test_compact_lines():
    res = {"old": "a", "new": "b",
           "summary": {"matched": 2, "changed": 1, "added": 0, "removed": 0},
           "changed": [{"name": "copy", "similarity": 0.5, "added": 1, "removed": 1,
                        "diff": ["--- copy(old)", "+++ copy(new)", "-call <strcpy>", "+call <strncpy>"]}],
           "added_functions": [], "removed_functions": []}
    lines = bindiff._compact_lines(res)
    assert any("CHANGED" in ln for ln in lines)
    assert any("copy" in ln and "similarity" in ln for ln in lines)


def test_main_no_args_returns_2(capsys):
    assert bindiff.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()
