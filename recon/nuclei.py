"""Run nuclei and return compact, severity-ranked findings for an LLM.

nuclei is the community's template-based vulnerability scanner (thousands of checks
for CVEs, misconfigs, exposures). Its raw output is huge and noisy; this wraps it,
parses the JSONL, de-duplicates, and returns a tight severity-ranked list — the
signal without the scroll. Optionally scope by severity/tags so the model gets
exactly what it asked for.

Requires ``nuclei`` on the host (Kali: ``apt install nuclei``; run ``nuclei -update-templates``
once). Meant to run where nuclei lives.

Dependencies: standard library. Wraps the external ``nuclei`` binary.

Safety: nuclei sends active probes to the TARGET — only scan hosts you're authorized
to. It does not touch the host filesystem. This wrapper adds no intrusive behavior.

Usage:
    python -m recon.nuclei https://target.example.com
    python -m recon.nuclei https://target.example.com --severity critical,high --json
    python -m recon.nuclei https://target.example.com --tags cve,exposure
"""

from __future__ import annotations

import argparse
import json
import sys

from common import proc
from common.output import emit, log

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _nuclei() -> str | None:
    for c in ("nuclei", "/usr/bin/nuclei"):
        if proc.have(c):
            return c
    return None


def run(target: str, *, severity: str = "", tags: str = "", templates: str = "",
        rate_limit: int = 150, timeout: float = 600.0) -> dict:
    """Scan ``target`` with nuclei; return parsed, ranked findings."""
    nb = _nuclei()
    if not nb:
        raise FileNotFoundError("nuclei not found (apt install nuclei; then nuclei -update-templates)")
    argv = [nb, "-u", target, "-jsonl", "-silent", "-no-color",
            "-disable-update-check", "-rate-limit", str(rate_limit), "-timeout", "10"]
    if severity:
        argv += ["-severity", severity]
    if tags:
        argv += ["-tags", tags]
    if templates:
        argv += ["-t", templates]

    log(f"[*] nuclei scanning {target} (this can take a while) ...")
    ran = proc.run(argv, timeout=timeout)
    findings, seen = [], set()
    for line in ran.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        key = (d.get("template-id"), d.get("matched-at") or d.get("host"))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "template": d.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "unknown").lower(),
            "matched_at": d.get("matched-at") or d.get("host", ""),
            "type": d.get("type", ""),
            "description": (info.get("description") or "").strip()[:200],
        })
    findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 5), f["template"]))
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {"target": target, "total": len(findings), "by_severity": by_sev,
            "findings": findings, "nuclei_stderr": ran.stderr[-500:] if not findings else ""}


def _compact_lines(res: dict) -> list[str]:
    sev = res["by_severity"]
    order = sorted(sev, key=lambda s: _SEV_ORDER.get(s, 5))
    lines = [f"# nuclei: {res['target']}  ({res['total']} findings)",
             "# by severity: " + (", ".join(f"{s}={sev[s]}" for s in order) or "none")]
    for f in res["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['name']}  ({f['template']})")
        lines.append(f"    at: {f['matched_at']}")
        if f["description"]:
            lines.append(f"    {f['description']}")
    if not res["findings"] and res.get("nuclei_stderr"):
        lines.append("# (no findings; nuclei note: " + res["nuclei_stderr"].strip()[:200] + ")")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.nuclei", description="Run nuclei and return ranked, de-duplicated findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m recon.nuclei https://target\n"
               "  python -m recon.nuclei https://target --severity critical,high\n")
    p.add_argument("target", nargs="?", help="Target URL/host.")
    p.add_argument("--severity", default="", help="e.g. critical,high,medium.")
    p.add_argument("--tags", default="", help="Template tags, e.g. cve,exposure,misconfig.")
    p.add_argument("--templates", default="", help="Specific template path/dir (-t).")
    p.add_argument("--rate-limit", type=int, default=150)
    p.add_argument("--timeout", type=float, default=600.0, help="Overall scan timeout (s).")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.target, severity=args.severity, tags=args.tags,
                  templates=args.templates, rate_limit=args.rate_limit, timeout=args.timeout)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
