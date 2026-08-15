from common import notes


def test_append_and_read(tmp_path):
    f = str(tmp_path / "n.md")
    notes.append("SQLi in /search q= (union)", f)
    notes.append("creds admin:hunter2", f)
    res = notes.read(f)
    assert res["exists"]
    assert "SQLi in /search" in res["content"]
    assert "creds admin:hunter2" in res["content"]
    assert "Engagement notes" in res["content"]     # header written once


def test_read_missing(tmp_path):
    res = notes.read(str(tmp_path / "nope.md"))
    assert res["exists"] is False and res["content"] == ""


def test_clear(tmp_path):
    f = str(tmp_path / "n.md")
    notes.append("x", f)
    notes.clear(f)
    assert notes.read(f)["content"] == ""


def test_run_unknown_action():
    import pytest
    with pytest.raises(ValueError):
        notes.run("delete")


def test_main_no_args(capsys):
    assert notes.main([]) == 2
    assert notes.main(["append"]) == 2               # append needs content
