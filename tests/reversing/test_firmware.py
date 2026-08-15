import os

import pytest

from common import proc
from reversing import firmware

SCAN_OUT = """\

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
20            0x14            Squashfs filesystem, little endian, version 4.0
1024          0x400           gzip compressed data
"""


def test_scan_parse(monkeypatch):
    monkeypatch.setattr(firmware.proc, "run",
                        lambda *a, **k: proc.Ran(["binwalk"], 0, SCAN_OUT, "", True))
    sigs = firmware._scan("binwalk", "fw.bin")
    assert sigs[0] == {"offset": 20, "hex": "0x14",
                       "description": "Squashfs filesystem, little endian, version 4.0"}
    assert sigs[1]["offset"] == 1024


def test_classify_tree(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh", encoding="utf-8")
    (tmp_path / "etc" / "system.conf").write_text("x=1", encoding="utf-8")
    (tmp_path / "id_rsa").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
    (tmp_path / "init.sh").write_text("#!/bin/sh", encoding="utf-8")
    (tmp_path / "prog").write_bytes(b"\x7fELF\x02\x01\x01")
    tree = firmware._classify_tree(str(tmp_path))
    interesting = tree["interesting"]
    assert any("passwd" in p for p in interesting["credentials"])
    assert any("id_rsa" in p for p in interesting["keys-certs"])
    assert any("init.sh" in p for p in interesting["scripts"])
    assert "prog" in tree["binaries"]


def test_is_elf(tmp_path):
    elf = tmp_path / "a"
    elf.write_bytes(b"\x7fELFrest")
    notelf = tmp_path / "b"
    notelf.write_bytes(b"MZ")
    assert firmware._is_elf(str(elf)) is True
    assert firmware._is_elf(str(notelf)) is False


def test_main_no_args_returns_2(capsys):
    assert firmware.main([]) == 2


def test_run_no_binwalk(monkeypatch):
    monkeypatch.setattr(firmware, "_binwalk", lambda: None)
    with pytest.raises(FileNotFoundError):
        firmware.run("fw.bin")
