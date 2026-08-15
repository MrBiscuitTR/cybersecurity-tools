"""Bug-bounty aide: sweep a source repo for vulnerability patterns, then guide the hunt.

Clones (or opens) a codebase and greps it for a broad catalogue of vulnerability
signatures across languages and classes — memory-unsafe C, command injection, SQLi,
XSS, SSRF, path traversal, insecure deserialization, SSTI, XXE, weak crypto, hardcoded
secrets, JWT misuse, TOCTOU, open redirect, prototype pollution, IDOR hints, and more.
Every hit is a LEAD, not a conclusion: the tool gives the operator a ranked map of
where to look, and writes findings to a scratch notes file so they survive context
compaction. The real work — reading the code, tracing tainted data to a sink, and
chaining findings — is the operator's, steered by this tool's guidance.

Only run this when the user explicitly asks to hunt bugs in a repository.

Dependencies: standard library + ``ripgrep`` (rg) if present (falls back to grep).

Safety: read-only. Clones a repo (git) and greps files; never builds or runs the code.
Assess only code you're authorized to (your targets / in-scope bug-bounty programs).

Usage:
    python -m analyze.bughunt https://github.com/org/repo
    python -m analyze.bughunt /path/to/local/repo --json
    python -m analyze.bughunt ./repo --classes sqli,ssrf,command-injection
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile

from common import proc
from common.output import emit, log

# Each: (class, severity, [globs], regex, why). Globs empty = all files.
# Regexes are ripgrep/Rust-regex compatible (no look-around/backrefs).
PATTERNS: list[tuple] = [
    # --- memory safety (C/C++) ---
    ("memory-unsafe", "high", ["*.c", "*.cc", "*.cpp", "*.h", "*.hpp"], r"\bgets\s*\(",
     "gets(): unbounded stdin read into a buffer — textbook overflow"),
    ("memory-unsafe", "high", ["*.c", "*.cc", "*.cpp"], r"\bstrcpy\s*\(",
     "strcpy(): no bounds — overflow if source exceeds destination"),
    ("memory-unsafe", "high", ["*.c", "*.cc", "*.cpp"], r"\bstrcat\s*\(",
     "strcat(): unbounded concatenation"),
    ("memory-unsafe", "high", ["*.c", "*.cc", "*.cpp"], r"\b(sprintf|vsprintf)\s*\(",
     "sprintf(): unbounded format into a fixed buffer"),
    ("memory-unsafe", "medium", ["*.c", "*.cc", "*.cpp"], r"\bscanf\s*\([^)]*%s",
     "scanf(\"%s\"): no width limit"),
    ("memory-unsafe", "medium", ["*.c", "*.cc", "*.cpp"], r"\balloca\s*\(",
     "alloca(): attacker-influenced size -> stack clash"),
    ("memory-unsafe", "low", ["*.c", "*.cc", "*.cpp"], r"\b(memcpy|memmove|strncpy)\s*\(",
     "memcpy/strncpy: verify the length is bounded and unsigned"),
    ("format-string", "high", ["*.c", "*.cc", "*.cpp"],
     r"\b(printf|fprintf|snprintf|syslog|err|warn)\s*\(\s*[A-Za-z_]\w*\s*[,)]",
     "format string: a variable is used as the format argument"),
    ("integer-overflow", "medium", ["*.c", "*.cc", "*.cpp"],
     r"\b(malloc|calloc|realloc)\s*\([^)]*[*+]", "allocation size arithmetic -> integer overflow?"),
    ("command-exec", "high", ["*.c", "*.cc", "*.cpp"],
     r"\b(system|popen|execl|execlp|execvp|execve)\s*\(", "process exec — RCE if the arg is tainted"),

    # --- command injection (many langs) ---
    ("command-injection", "high", ["*.py"], r"os\.system\s*\(", "os.system() with user data -> RCE"),
    ("command-injection", "high", ["*.py"],
     r"subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
     "subprocess(shell=True) -> shell injection"),
    ("command-injection", "high", ["*.py"], r"\b(eval|exec)\s*\(", "eval/exec of dynamic input -> RCE"),
    ("command-injection", "high", ["*.js", "*.ts", "*.jsx", "*.tsx"],
     r"child_process\.(exec|execSync)\s*\(", "child_process.exec -> shell injection"),
    ("command-injection", "high", ["*.js", "*.ts"], r"\beval\s*\(|new\s+Function\s*\(",
     "eval()/Function() -> RCE"),
    ("command-injection", "high", ["*.php"],
     r"\b(system|exec|shell_exec|passthru|proc_open|popen|eval)\s*\(", "PHP command exec/eval"),
    ("command-injection", "high", ["*.java"], r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(",
     "Java process exec"),
    ("command-injection", "high", ["*.go"], r"exec\.Command\s*\(", "os/exec.Command — check args"),
    ("command-injection", "high", ["*.rb"], r"(`|%x\[|system\s*\(|Open3\.)", "Ruby command exec"),

    # --- SQL injection ---
    ("sqli", "high", ["*.py"], r"(execute|executemany)\s*\(\s*[f]?[\"'].*(%s|\{|\+|%\()",
     "SQL built via interpolation/concat in execute()"),
    ("sqli", "high", ["*.py", "*.js", "*.ts", "*.php", "*.java", "*.go"],
     r"(SELECT|INSERT|UPDATE|DELETE)\b[^;]{0,80}(\+|\$\{|%s\b|f[\"'])",
     "SQL string assembled from variables"),
    ("sqli", "medium", ["*.py"], r"\.raw\s*\(|RawSQL\s*\(", "ORM raw SQL"),
    ("sqli", "high", ["*.php"], r"mysqli?_query\s*\([^)]*\$_(GET|POST|REQUEST)",
     "SQL query with a raw superglobal"),

    # --- XSS / template ---
    ("xss", "high", ["*.jsx", "*.tsx", "*.js", "*.ts"], r"dangerouslySetInnerHTML",
     "React dangerouslySetInnerHTML — unescaped HTML"),
    ("xss", "high", ["*.js", "*.ts"], r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(",
     "DOM sink (innerHTML/document.write)"),
    ("xss", "high", ["*.vue"], r"v-html", "Vue v-html — unescaped"),
    ("xss", "high", ["*.php"], r"echo\s+\$_(GET|POST|REQUEST|COOKIE)", "echo of user input"),
    ("xss", "medium", ["*.html", "*.j2", "*.jinja", "*.jinja2"], r"\|\s*safe\b|autoescape\s+false",
     "template escaping disabled"),
    ("ssti", "high", ["*.py"], r"render_template_string\s*\(|Template\s*\([^)]*(\+|%|format|f[\"'])",
     "template built from a dynamic string -> SSTI"),

    # --- deserialization ---
    ("insecure-deserialization", "high", ["*.py"], r"\b(pickle|cPickle|_pickle)\.(load|loads)\s*\(",
     "pickle.loads() -> arbitrary code execution"),
    ("insecure-deserialization", "high", ["*.py"], r"yaml\.load\s*\(",
     "yaml.load() -> RCE unless SafeLoader is used (verify)"),
    ("insecure-deserialization", "high", ["*.php"], r"\bunserialize\s*\(", "PHP unserialize()"),
    ("insecure-deserialization", "high", ["*.java"], r"ObjectInputStream|\.readObject\s*\(",
     "Java native deserialization"),
    ("insecure-deserialization", "high", ["*.rb"], r"Marshal\.load|YAML\.load\b", "Ruby Marshal/YAML load"),
    ("insecure-deserialization", "high", ["*.js", "*.ts"], r"node-serialize|unserialize\s*\(",
     "node-serialize -> RCE"),

    # --- SSRF ---
    ("ssrf", "high", ["*.py"],
     r"requests\.(get|post|put|head|request)\s*\([^)]*(url|uri|target|host|link|endpoint|addr)",
     "outbound request to a variable URL -> SSRF"),
    ("ssrf", "medium", ["*.py"], r"urllib\.(request\.)?urlopen\s*\(", "urlopen(dynamic) -> SSRF"),
    ("ssrf", "high", ["*.js", "*.ts"], r"(axios|fetch|request|got|superagent)\s*\(?\s*(req\.|request\.|user|params)",
     "server-side request to user-controlled URL -> SSRF"),
    ("ssrf", "high", ["*.php"], r"(curl_exec|file_get_contents)\s*\([^)]*\$_(GET|POST|REQUEST)",
     "SSRF via user-controlled URL"),

    # --- path traversal / file ---
    ("path-traversal", "high", ["*.py"], r"open\s*\([^)]*(request|args|params|input|user|filename)",
     "open() on a user-controlled path"),
    ("path-traversal", "high", ["*.js", "*.ts"],
     r"(readFile|readFileSync|sendFile|createReadStream)\s*\([^)]*(req\.|request\.)",
     "file read with a user-controlled path"),
    ("path-traversal", "high", ["*.php"], r"(include|require)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST)",
     "LFI/RFI via include of user input"),
    ("path-traversal", "low", [], r"\.\./\.\./", "hardcoded traversal sequence"),

    # --- TOCTOU / temp ---
    ("toctou", "medium", ["*.c", "*.cpp", "*.py"], r"\baccess\s*\(",
     "access() then open() is a TOCTOU race — check for it"),
    ("insecure-temp", "medium", ["*.c", "*.cpp"], r"\b(tmpnam|tempnam|mktemp)\s*\(",
     "predictable temp filename"),
    ("insecure-temp", "medium", ["*.py"], r"tempfile\.mktemp\s*\(", "tempfile.mktemp is insecure"),

    # --- crypto / secrets ---
    ("weak-crypto", "medium", [], r"\b(md5|MD5)\b|hashlib\.md5", "MD5 — broken for integrity/passwords"),
    ("weak-crypto", "medium", [], r"\b(sha1|SHA1)\b|hashlib\.sha1", "SHA1 — weak"),
    ("weak-crypto", "high", [], r"\bDES\b|MODE_ECB|\bECB\b|\bRC4\b", "insecure cipher/mode (DES/ECB/RC4)"),
    ("weak-random", "medium", ["*.js", "*.ts"], r"Math\.random\s*\(", "Math.random — not cryptographically secure"),
    ("weak-random", "medium", ["*.py"], r"\brandom\.(random|randint|choice|randrange)\s*\(",
     "random module — not secure for tokens/secrets"),
    ("hardcoded-secret", "high", [],
     r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\s*[:=]\s*[\"'][^\"']{6,}",
     "hardcoded credential/secret"),
    ("jwt", "high", [], r"algorithms\s*=\s*\[\s*\]|verify\s*=\s*False|alg['\"]?\s*[:=]\s*['\"]none",
     "JWT verification disabled or alg=none"),

    # --- XXE ---
    ("xxe", "high", ["*.py"], r"etree\.(parse|fromstring)|XMLParser\s*\(|xml\.dom|minidom\.parse",
     "XML parse — ensure external entities/DTDs are disabled (XXE)"),
    ("xxe", "high", ["*.java"], r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory",
     "XML parser — disable DTDs/external entities (XXE)"),

    # --- redirect / authz / pollution / config ---
    ("open-redirect", "medium", ["*.py"], r"redirect\s*\(\s*(request\.(args|values|GET|form)|url)",
     "redirect to a user-controlled URL -> open redirect"),
    ("open-redirect", "medium", ["*.js", "*.ts"], r"res\.redirect\s*\(\s*(req\.|request\.)",
     "open redirect"),
    ("idor-authz", "low", [],
     r"(request|req)\.(args|params|query|body|GET|POST)\[?['\"]?(id|user_?id|account|uid)",
     "object id taken from request — verify an ownership/authorization check exists"),
    ("prototype-pollution", "medium", ["*.js", "*.ts"], r"(Object\.assign|_\.merge|deepMerge|extend)\s*\(",
     "recursive merge/assign — prototype pollution if keys are user-controlled"),
    ("debug-backdoor", "medium", ["*.py"], r"DEBUG\s*=\s*True|debug\s*=\s*True\)",
     "debug mode enabled — verbose errors / interactive debugger"),
    ("debug-backdoor", "high", [], r"(?i)\b(backdoor|magic_?(login|password|key)|master_?password)\b",
     "suspicious backdoor-like identifier"),
    ("cors", "medium", [], r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']?\*",
     "wildcard CORS (dangerous with credentials)"),
]


def _rg() -> str | None:
    for c in ("rg", "/usr/bin/rg"):
        if proc.have(c):
            return c
    return None


def _clone(url: str) -> str:
    dest = tempfile.mkdtemp(prefix="bughunt_")
    log(f"[*] cloning {url} (shallow) ...")
    ran = proc.run(["git", "clone", "--depth", "1", "--quiet", url, dest], timeout=300)
    if ran.code != 0:
        raise ValueError(f"git clone failed: {ran.stderr.strip()[:200]}")
    return dest


def _search(rg: str, repo: str, pattern: str, globs: list[str], per_pattern: int) -> list[tuple]:
    argv = [rg, "--no-heading", "-n", "--color=never", "--max-columns", "220", "-e", pattern]
    for g in globs:
        argv += ["--glob", g]
    argv += [repo]
    ran = proc.run(argv, timeout=120)
    hits = []
    for line in ran.stdout.splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)$", line)
        if m:
            hits.append((os.path.relpath(m.group(1), repo).replace(os.sep, "/"),
                         int(m.group(2)), m.group(3).strip()[:180]))
        if len(hits) >= per_pattern:
            break
    return hits


def run(target: str, *, classes: list[str] | None = None, per_pattern: int = 15,
        max_total: int = 400) -> dict:
    """Sweep ``target`` (repo URL or local path) for vulnerability patterns."""
    rg = _rg()
    if not rg:
        raise FileNotFoundError("ripgrep (rg) not found — apt install ripgrep")
    repo = _clone(target) if re.match(r"^(https?://|git@)", target) else target
    if not os.path.isdir(repo):
        raise FileNotFoundError(f"not a directory: {repo}")

    wanted = set(classes) if classes else None
    findings: list[dict] = []
    log(f"[*] sweeping {len(PATTERNS)} patterns over {repo} ...")
    for cls, sev, globs, pattern, why in PATTERNS:
        if wanted and cls not in wanted:
            continue
        for path, line, snippet in _search(rg, repo, pattern, globs, per_pattern):
            findings.append({"class": cls, "severity": sev, "file": path,
                             "line": line, "snippet": snippet, "why": why})
            if len(findings) >= max_total:
                break
        if len(findings) >= max_total:
            break

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 3), f["class"], f["file"]))
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}
    by_class: dict[str, int] = {}
    for f in findings:
        by_class[f["class"]] = by_class.get(f["class"], 0) + 1

    notes_path = _write_notes(repo, target, findings, by_sev, by_class)
    return {"target": target, "repo_path": repo, "total": len(findings),
            "by_severity": by_sev, "by_class": by_class, "findings": findings,
            "notes_file": notes_path}


def _write_notes(repo: str, target: str, findings, by_sev, by_class) -> str:
    path = os.path.join(repo, "BUGHUNT_NOTES.md")
    lines = [f"# Bug-hunt notes — {target}", "",
             f"Automated sweep: {len(findings)} leads "
             f"(high={by_sev['high']} medium={by_sev['medium']} low={by_sev['low']}).",
             "", "## Leads (verify each — a match is a starting point, not a bug)"]
    for f in findings:
        lines.append(f"- [ ] **{f['severity']}** `{f['class']}` {f['file']}:{f['line']} — "
                     f"`{f['snippet']}`  ({f['why']})")
    lines += ["", "## Confirmed / interesting (append as you go — SURVIVES compaction)",
              "<!-- For each real finding: sink, source, tainted path, PoC idea, severity, and",
              "     how it chains with others. Keep entries brief but complete. -->", ""]
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except OSError:
        return ""
    return path


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# bughunt: {res['target']}  ({res['total']} leads)",
             f"# by severity: high={res['by_severity']['high']} "
             f"medium={res['by_severity']['medium']} low={res['by_severity']['low']}",
             f"# by class: " + ", ".join(f"{k}={v}" for k, v in sorted(res['by_class'].items())),
             f"# NOTES written to: {res['notes_file']}  (append confirmed findings here)"]
    for sev in ("high", "medium"):
        sf = [f for f in res["findings"] if f["severity"] == sev]
        if sf:
            lines.append(f"## {sev.upper()} leads")
            lines += [f"[{f['class']}] {f['file']}:{f['line']}  {f['snippet']}" for f in sf[:80]]
    lines.append("# next: read each HIGH lead in context (bash: rg/sed to view), trace the "
                 "tainted input to the sink, and note confirmed issues in the notes file.")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyze.bughunt",
        description="Sweep a source repo for vulnerability patterns (bug-bounty aide).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m analyze.bughunt https://github.com/org/repo\n"
               "  python -m analyze.bughunt ./repo --classes sqli,ssrf\n")
    p.add_argument("target", nargs="?", help="Repo URL (cloned) or local path.")
    p.add_argument("--classes", help="Comma-separated subset of vuln classes to check.")
    p.add_argument("--per-pattern", type=int, default=15, help="Max hits per pattern.")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    classes = [c.strip() for c in args.classes.split(",")] if args.classes else None
    try:
        res = run(args.target, classes=classes, per_pattern=args.per_pattern)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
