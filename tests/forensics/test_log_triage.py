import os
import tempfile

import pytest

from forensics import log_triage

SAMPLE = """\
Aug 15 10:00:01 h sshd[1]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2
Aug 15 10:00:02 h sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2
Aug 15 10:00:03 h sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2
Aug 15 10:00:04 h sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2
Aug 15 10:00:05 h sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2
Aug 15 10:00:06 h sshd[1]: Invalid user oracle from 10.0.0.9
Aug 15 10:00:07 h sshd[1]: Accepted publickey for kali from 10.0.0.2 port 22 ssh2
1.2.3.4 - - [15/Aug/2026:10:00:00 +0000] "GET /a?id=1 union select x from y HTTP/1.1" 200 1 "-" "sqlmap/1.7"
1.2.3.5 - - [15/Aug/2026:10:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 404 1 "-" "curl/8"
"""


@pytest.fixture
def logfile(tmp_path):
    p = tmp_path / "t.log"
    p.write_text(SAMPLE, encoding="utf-8")
    return str(p)


def test_ssh_brute_force(logfile):
    res = log_triage.run(logfile)
    bf = res["ssh"]["brute_force"]
    assert bf and bf[0]["ip"] == "10.0.0.9" and bf[0]["fails"] == 5
    assert "root" in bf[0]["users"]


def test_ssh_success_and_invalid(logfile):
    res = log_triage.run(logfile)
    assert {"user": "kali", "ip": "10.0.0.2"} in res["ssh"]["successful_logins"]
    assert ("oracle", 1) in res["ssh"]["top_invalid_users"]


def test_web_attacks_and_scanners(logfile):
    res = log_triage.run(logfile)
    types = res["web"]["attacks_by_type"]
    assert types.get("sqli") == 1 and types.get("traversal") == 1
    tools = {s["tool"] for s in res["web"]["scanners"]}
    assert "sqlmap" in tools and "curl" in tools


def test_compact_lines(logfile):
    lines = log_triage._compact_lines(log_triage.run(logfile))
    assert any("BRUTE-FORCE" in ln for ln in lines)
    assert any("[sqli]" in ln for ln in lines)


def test_main_no_args_returns_2(capsys):
    assert log_triage.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()
