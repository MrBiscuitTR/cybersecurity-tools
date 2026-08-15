from reversing import decompile

LIST_OUT = """\
noise before
@@@BEGIN@@@ mode=list program=secret
@@@IMPORTS@@@
  puts
  strcmp
@@@FUNCTIONS@@@
  main @ 00101180 size=83
  check @ 00101149 size=55
@@@STRINGS@@@
  0010047e: hunter2
@@@END@@@
log noise after
"""

FUNC_OUT = """\
@@@BEGIN@@@ mode=func program=secret
@@@FUNC@@@ check @ 00101149
bool check(char *p)
{
WARN  something ghidra logged
  return strcmp(p,"hunter2") == 0;
}
@@@FUNC@@@ main @ 00101180
int main(void) { return 0; }
@@@END@@@
"""


def test_slice_extracts_between_markers():
    body = decompile._slice(LIST_OUT)
    assert body.startswith("@@@BEGIN@@@") and "noise before" not in body
    assert "log noise after" not in body


def test_parse_list():
    res = decompile._parse_list(LIST_OUT)
    assert res["imports"] == ["puts", "strcmp"]
    assert "main @ 00101180 size=83" in res["functions"]
    assert any("hunter2" in s for s in res["strings"])


def test_parse_funcs_and_log_filter():
    funcs = decompile._parse_funcs(FUNC_OUT)
    names = [f["name"] for f in funcs]
    assert names == ["check", "main"]
    check = funcs[0]
    assert check["address"] == "00101149"
    assert "hunter2" in check["code"]
    assert "WARN" not in check["code"]          # ghidra log line filtered out


def test_find_headless_missing(monkeypatch):
    monkeypatch.setattr(decompile.proc, "have", lambda b: False)
    monkeypatch.setattr(decompile.os.path, "exists", lambda p: False)
    monkeypatch.setattr(decompile.os, "environ", {}, raising=False)
    assert decompile._find_headless() is None


def test_run_without_ghidra_raises(monkeypatch):
    monkeypatch.setattr(decompile, "_find_headless", lambda: None)
    import pytest
    with pytest.raises(FileNotFoundError):
        decompile.run("whatever", mode="list")


def test_main_no_args_returns_2(capsys):
    assert decompile.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_main_missing_ghidra_returns_1(monkeypatch, capsys):
    monkeypatch.setattr(decompile, "_find_headless", lambda: None)
    assert decompile.main(["/tmp/whatever"]) == 1
    assert "analyzeheadless" in capsys.readouterr().err.lower()
