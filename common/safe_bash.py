"""A safe, AI-facing shell runner: policy-gated command execution.

The autonomous operator needs a shell (rg/grep/find/git/curl/objdump/...), but must
NOT be able to wreck the host. This module runs a command only after it passes a
deny policy, then captures output with a context-friendly cap.

The policy is defense-in-depth, NOT an OS jail: it blocks the obvious ways to damage
or take over the host — destructive filesystem ops (rm/mv/dd/shred/truncate),
permission/ownership changes (chmod/chown), disk/mount/system-state changes, privilege
escalation (sudo/su), user/persistence changes, package installs (arbitrary code), git
history mutation, in-place edits (sed -i), pipe-download-to-shell, and redirects that
overwrite device/system files. Run it as a non-root user; treat the policy as a
seatbelt, not a vault.

What is ALLOWED: read-only recon and analysis — rg, grep, find, cat/head/tail, ls,
file, stat, wc, sort/uniq/cut/awk, sed (non -i), git clone/log/show/diff/grep/blame,
curl/wget (fetching), xxd/strings/objdump/nm/readelf, python3, and pipes/&&/;/subshells
between them. Redirects to /tmp, the working dir, and /dev/null are fine.

Dependencies: standard library only.

Safety: THIS FILE is the guardrail. Changes here affect every tool that shells out.
Keep the denylist conservative; when in doubt, block.

Usage:
    python -m common.safe_bash "rg -n 'strcpy' src/"
    python -m common.safe_bash --cwd /repo "git log --oneline -5" --json
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# --- policy: denied leading binaries (basename of each pipeline segment) -----
_DENY_BINARIES = {
    # destructive filesystem
    "rm", "rmdir", "unlink", "shred", "srm", "wipe", "wipefs", "mv", "dd",
    "truncate", "ln", "rename",
    # permissions / attributes / ownership
    "chmod", "chown", "chgrp", "chattr", "setfacl",
    # disk / filesystem / mount
    "mkfs", "mke2fs", "mkdosfs", "mkswap", "fdisk", "cfdisk", "sgdisk", "parted",
    "gparted", "badblocks", "fdformat", "mount", "umount", "swapon", "swapoff",
    "losetup", "cryptsetup",
    # system state / services / net config
    "reboot", "shutdown", "halt", "poweroff", "init", "telinit", "systemctl",
    "service", "sysctl", "kill", "pkill", "killall", "iptables", "ip6tables",
    "nft", "ufw", "firewall-cmd",
    # privilege escalation
    "sudo", "su", "doas", "pkexec",
    # users / persistence
    "passwd", "useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd",
    "chpasswd", "visudo", "adduser", "deluser", "crontab", "at", "batch",
    # package managers (arbitrary code on install)
    "apt", "apt-get", "aptitude", "dpkg", "yum", "dnf", "rpm", "pacman", "zypper",
    "pip", "pip3", "npm", "pnpm", "yarn", "gem", "cargo", "brew", "snap", "flatpak",
    "gimp",  # (placeholder guard; harmless)
}

# --- policy: denied patterns anywhere in the command (case-insensitive) ------
_DENY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r":\s*\(\s*\)\s*\{.*\}\s*;\s*:", re.S), "fork bomb"),
    (re.compile(r"(curl|wget|fetch)\b[^|&;]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|perl|ruby)\b"),
     "pipe-download-to-shell"),
    (re.compile(r"\bof\s*=\s*/dev/"), "raw write to a device (dd of=/dev/...)"),
    (re.compile(r">\s*/dev/(?!null|stdout|stderr|tty)\S"), "redirect overwriting a device"),
    (re.compile(r">{1,2}\s*/(etc|usr|bin|sbin|boot|lib|lib64|sys|proc|root|var/lib|var/spool)\b"),
     "redirect overwriting a system path"),
    (re.compile(r">{1,2}\s*~?/?\.?(ssh|bash_history|bashrc|bash_profile|profile|"
                r"authorized_keys|zshrc)\b"), "redirect overwriting a shell/ssh config"),
    (re.compile(r"\bgit\s+(push|reset\s+--hard|clean\b|filter-branch|update-ref|"
                r"checkout\s+--\s|rm\b)"), "git history/worktree mutation"),
    (re.compile(r"\b(sed|perl|ruby)\s+.*-i\b"), "in-place file edit (-i)"),
    (re.compile(r"\bmkfs\S*"), "filesystem creation"),
    (re.compile(r"\bchmod\s+.*\s/(?:\s|$|etc|usr|bin|root)"), "chmod on a system path"),
]

# env-assignment prefix (FOO=bar cmd), and pipeline/sequence separators.
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")
_SEGMENT_SPLIT = re.compile(r"\|\||&&|\||;|\n|&")


def _segments(command: str) -> list[str]:
    """Split into pipeline/sequence segments (quote-naive; errs toward more segments)."""
    return [s.strip() for s in _SEGMENT_SPLIT.split(command) if s.strip()]


def _leading_binary(segment: str) -> str:
    """Basename of the first real token of a segment (skipping env assignments,
    subshell/paren wrappers, and command substitution openers)."""
    seg = segment.lstrip("([{ \t")
    for tok in seg.split():
        if _ENV_ASSIGN.match(tok):
            continue
        tok = tok.strip("`'\"")
        # strip a leading path: /usr/bin/rm -> rm
        return tok.rsplit("/", 1)[-1]
    return ""


def check(command: str) -> tuple[bool, str]:
    """Return (allowed, reason). ``reason`` is empty when allowed."""
    if not command.strip():
        return False, "empty command"
    low = command.lower()
    for rx, why in _DENY_PATTERNS:
        if rx.search(low):
            return False, f"blocked: {why}"
    # Check the leading binary of every segment, including those hidden inside
    # command substitutions ($(...) / `...`), against the denylist.
    subst = re.findall(r"\$\(([^)]*)\)|`([^`]*)`", command)
    extra = [a or b for a, b in subst]
    for seg in _segments(command) + [s for e in extra for s in _segments(e)]:
        binary = _leading_binary(seg)
        if binary in _DENY_BINARIES:
            return False, f"blocked: '{binary}' is a disallowed command (host-safety policy)"
    return True, ""


def run(command: str, *, cwd: str | None = None, timeout: float = 60.0,
        max_lines: int = 400) -> dict:
    """Check the policy, then run the command (via /bin/sh) and capture output.

    Returns {command, allowed, blocked_reason, exit_code, stdout, stderr, truncated,
             duration_s}. If blocked, it is NOT executed.
    """
    allowed, reason = check(command)
    if not allowed:
        return {"command": command, "allowed": False, "blocked_reason": reason,
                "exit_code": None, "stdout": "", "stderr": "", "truncated": False}
    import time
    t0 = time.time()
    try:
        p = subprocess.run(command, shell=True, cwd=cwd, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as exc:
        code = -2
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") + f"\n[timed out after {timeout}s]" if isinstance(exc.stderr, str) \
            else f"[timed out after {timeout}s]"
    out, trunc = _truncate(out, max_lines)
    return {"command": command, "allowed": True, "blocked_reason": "",
            "exit_code": code, "stdout": out, "stderr": err[:8000],
            "truncated": trunc, "duration_s": round(time.time() - t0, 2)}


def _truncate(text: str, max_lines: int) -> tuple[str, bool]:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text, False
    head = lines[: max_lines * 3 // 5]
    tail = lines[-(max_lines * 2 // 5):]
    omitted = len(lines) - len(head) - len(tail)
    return "\n".join(head + [f"... [{omitted} lines omitted — narrow your command] ..."] + tail), True


def _compact_lines(res: dict) -> list[str]:
    if not res["allowed"]:
        return [f"# safe_bash: BLOCKED — {res['blocked_reason']}",
                f"$ {res['command']}",
                "# rewrite without the disallowed operation (this is a host-safety guard)."]
    lines = [f"$ {res['command']}   (exit={res['exit_code']}"
             + (", TRUNCATED" if res["truncated"] else "") + ")"]
    if res["stdout"]:
        lines.append(res["stdout"])
    if res["stderr"].strip():
        lines.append("# stderr:")
        lines.append(res["stderr"])
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="common.safe_bash",
        description="Run a shell command through the host-safety policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python -m common.safe_bash \"rg -n gets src/\"\n")
    p.add_argument("command", nargs="?", help="Command to run.")
    p.add_argument("--cwd", default=None, help="Working directory.")
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--max-lines", type=int, default=400)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help(sys.stderr)
        return 2
    from common.output import emit
    res = run(args.command, cwd=args.cwd, timeout=args.timeout, max_lines=args.max_lines)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0 if res["allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
