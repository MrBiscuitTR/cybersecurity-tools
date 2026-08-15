"""Safe subprocess capture for tools that wrap existing binaries.

Many tools here are thin, well-documented wrappers over software already on the
Kali box (tshark, strings, xxd, ...). This module runs them **read-only**, with
an argument *list* (never a shell string, so nothing gets interpolated), a
timeout, and full stdout/stderr captured for the model to read.

It will not run anything through a shell and does not modify the filesystem.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Ran:
    """Outcome of a subprocess call."""

    argv: list[str]
    code: int          # exit code; -1 if the binary was missing, -2 on timeout
    stdout: str
    stderr: str
    found: bool        # was the binary present on PATH?


def have(binary: str) -> bool:
    """True if ``binary`` is on PATH. Use this to give the operator a precise
    'install X' message instead of a stack trace."""
    return shutil.which(binary) is not None


def run(argv: list[str], *, timeout: float = 60.0, input_text: str | None = None) -> Ran:
    """Run ``argv`` (a list, not a string) and capture everything.

    Args:
        argv: Command and args, e.g. ``["tshark", "-r", path, "-q", "-z", "io,phs"]``.
        timeout: Kill and return code -2 after this many seconds.
        input_text: Optional stdin.

    Returns:
        A :class:`Ran`. Never raises for a missing binary or a non-zero exit;
        check ``.found`` and ``.code``.
    """
    if not argv:
        return Ran([], -1, "", "empty command", False)
    if not have(argv[0]):
        return Ran(argv, -1, "", f"binary not found on PATH: {argv[0]}", False)
    try:
        p = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",       # tools like tshark emit UTF-8 (e.g. the "->" arrow);
            errors="replace",       # don't let the Windows locale (cp1252) mangle it.
            timeout=timeout,
            shell=False,
        )
        return Ran(argv, p.returncode, p.stdout, p.stderr, True)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = (exc.stderr or "") + f"\n[timed out after {timeout}s]"
        out = out.decode() if isinstance(out, bytes) else out
        err = err.decode() if isinstance(err, bytes) else err
        return Ran(argv, -2, out, err, True)
