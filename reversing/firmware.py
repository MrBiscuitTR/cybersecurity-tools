"""Analyze and unpack firmware images with binwalk — and surface the loot.

Firmware blobs (router/IoT ``.bin`` files) embed filesystems (SquashFS, JFFS2,
CramFS, ...), bootloaders, and compressed archives. This wraps ``binwalk`` to:

  scan (default)   list embedded signatures (offset, type) — what's in the blob
  --extract        carve everything out (filesystems included) and then TRIAGE the
                   extracted tree: config files, credentials, keys/certs, and the
                   embedded binaries you'll want to decompile next

The point isn't just "extracted N files" — it's handing the operator the passwd
file, the hardcoded ``admin_password=...`` in a config, the private keys, and the
list of ELF binaries, all in one compact report.

Requires ``binwalk`` (and its extractors: squashfs-tools, jefferson, etc.) on the
host — meant to run where those live (the Kali box).

Dependencies: standard library; reuses this repo's secret scanner. Wraps external
``binwalk`` (read-only on the input; extraction writes to a scratch dir, never to
the source image; nothing is executed).

Usage:
    python -m reversing.firmware firmware.bin
    python -m reversing.firmware firmware.bin --extract
    python -m reversing.firmware firmware.bin --extract --recursive --json
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import tempfile

from common import proc
from common.output import emit, log

# Interesting file classifiers for the extracted tree (name/path based).
_CLASSIFY = [
    ("credentials", re.compile(r"(?i)(^|/)(etc/)?(passwd|shadow|\.htpasswd|"
                              r"chap-secrets|ppp/.*secrets)$")),
    ("keys-certs", re.compile(r"(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|"
                             r"\.(pem|key|crt|cer|der|p12|pfx|pub)$)")),
    ("config", re.compile(r"(?i)(^|/)(etc/).*|(\.(conf|cfg|ini|xml|json|env|toml)$)|"
                         r"(^|/)(config|nvram|defaults)")),
    ("scripts", re.compile(r"(?i)(\.(sh|py|pl|lua)$)|(^|/)(rcS|init|preinit|inittab)$")),
]


def _binwalk() -> str | None:
    for c in ("binwalk", "/usr/bin/binwalk", "/usr/local/bin/binwalk"):
        if proc.have(c) or os.path.exists(c):
            return c
    return None


def _scan(binwalk: str, path: str) -> list[dict]:
    ran = proc.run([binwalk, path], timeout=180)
    sigs = []
    for line in ran.stdout.splitlines():
        m = re.match(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", line)
        if m:
            sigs.append({"offset": int(m.group(1)), "hex": m.group(2),
                         "description": m.group(3).strip()})
    return sigs


def _is_elf(fp: str) -> bool:
    try:
        with open(fp, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _classify_tree(root: str) -> dict:
    buckets: dict[str, list] = {name: [] for name, _ in _CLASSIFY}
    binaries, all_files = [], []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            fp = os.path.join(dirpath, name)
            rel = os.path.relpath(fp, root).replace(os.sep, "/")  # normalize for regex + output
            all_files.append(rel)
            for label, rx in _CLASSIFY:
                if rx.search(rel):
                    buckets[label].append(rel)
                    break
            if _is_elf(fp):
                binaries.append(rel)
    return {"all_files": sorted(all_files), "binaries": sorted(binaries),
            "interesting": {k: sorted(v) for k, v in buckets.items() if v}}


def run(path: str, *, extract: bool = False, recursive: bool = False) -> dict:
    """Scan (and optionally extract+triage) a firmware image."""
    binwalk = _binwalk()
    if not binwalk:
        raise FileNotFoundError("binwalk not found. Kali: apt install binwalk")
    if not os.path.exists(path):
        raise FileNotFoundError(f"file not found: {path}")

    log(f"[*] binwalk scanning {path} ...")
    result = {"file": path, "signatures": _scan(binwalk, path)}
    if not extract:
        return result

    outdir = tempfile.mkdtemp(prefix="firmware_")
    argv = [binwalk, "-e", "-C", outdir]
    if recursive:
        argv += ["-M", "-d", "4"]
    argv.append(path)
    log(f"[*] extracting to {outdir} ...")
    proc.run(argv, timeout=600)
    extracted = glob.glob(os.path.join(outdir, "_*.extracted"))
    root = extracted[0] if extracted else outdir
    tree = _classify_tree(root)

    # Triage extracted files for hardcoded secrets (reuse the secret scanner).
    from recon.secrets_scan import run as scan_secrets
    secrets = scan_secrets(root).get("findings", [])

    result.update({"extracted_root": root, **tree, "secrets": secrets})
    return result


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# firmware: {res['file']}"]
    if res["signatures"]:
        lines.append("## embedded signatures (offset  type)")
        lines += [f"  {s['hex']:>10}  {s['description']}" for s in res["signatures"]]
    else:
        lines.append("# no known signatures found")
    if "extracted_root" not in res:
        return lines
    lines.append(f"## extracted -> {res['extracted_root']}  ({len(res['all_files'])} files)")
    for label, items in res.get("interesting", {}).items():
        lines.append(f"### {label}")
        lines += [f"  {p}" for p in items]
    if res.get("binaries"):
        lines.append(f"### binaries ({len(res['binaries'])}) — decompile/triage these")
        lines += [f"  {p}" for p in res["binaries"]]
    if res.get("secrets"):
        lines.append(f"### HARDCODED SECRETS ({len(res['secrets'])})")
        lines += [f"  [{s['type']}] {s['file']}:{s['line']}  {s['match']}" for s in res["secrets"]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reversing.firmware",
        description="Scan/unpack firmware images with binwalk and triage the contents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m reversing.firmware firmware.bin\n"
                "  python -m reversing.firmware firmware.bin --extract --json\n"),
    )
    p.add_argument("file", nargs="?", help="Firmware image / blob to analyze.")
    p.add_argument("--extract", action="store_true", help="Carve out embedded files and triage them.")
    p.add_argument("--recursive", action="store_true", help="Matryoshka: recurse into extracted files.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.file:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.file, extract=args.extract, recursive=args.recursive)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
