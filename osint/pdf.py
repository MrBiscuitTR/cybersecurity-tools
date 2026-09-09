"""Get text out of PDFs — CVs, certificates, conference bios, scanned letters.

A CV is very often the only document where somebody publishes a phone number or
a postal address, and CVs are PDFs. Extraction runs in three tiers, best first,
and reports which tier produced the text so a caller knows how much to trust it:

    pdftotext   poppler-utils, if installed. Handles font encodings, ToUnicode
                CMaps, ligatures and column layout properly. Always preferred.
    pypdf       the pure-Python library (pip install pypdf). Nearly as good, no
                system package needed. Preferred over the builtin parser.
    builtin     a stdlib content-stream parser (below). Last resort so the tool
                still works with no dependencies at all.
    ocr         tesseract, if installed, for PDFs that contain no text layer at
                all — a scan or an exported image. Without OCR those files are
                genuinely unreadable, and the tool says so rather than returning
                the binary noise a naive parser produces.

Why the builtin parser is not just "regex for (...)":

  * Text is shown with ``TJ`` arrays that interleave string fragments with
    kerning numbers: ``[(r) -12 (ec) -8 (ogniz) -15 (es)] TJ``. Joining those
    fragments with spaces yields "r ec ogniz es" — and turns an email address
    into several unusable fragments. Fragments are concatenated with nothing,
    and a space is inserted only where the kerning is large enough to be a real
    word gap.
  * Image streams contain byte sequences that look exactly like PDF string
    literals. Parsing those produces pages of garbage, so only streams that
    actually contain text operators are read.
  * Strings come as literals ``(...)`` with octal/backslash escapes, or as hex
    ``<0048...>``, and may be UTF-16BE. All three are handled.

Optional dependencies (everything degrades cleanly without them):
    pypdf       pip install pypdf

External binaries (both optional, wrapped read-only via ``common.proc``):
    pdftotext   apt install poppler-utils
    tesseract   apt install tesseract-ocr  (plus a language pack, e.g.
                tesseract-ocr-tur for Turkish)

Safety: read-only. Parses bytes you already fetched. The optional binaries are
run with an argument list on a temporary copy and never with a shell.

Usage:
    python -m osint.pdf cv.pdf
    python -m osint.pdf cv.pdf --json
    python -m osint.pdf https://example.com/cv.pdf --ocr --region TR
"""

from __future__ import annotations

import argparse
import os
import io
import re
import sys
import tempfile
import zlib

from common import proc
from common.output import emit, log

# `stream` may be followed by CRLF, LF or (in sloppy writers) CR or nothing.
_STREAM_RE = re.compile(rb"stream[\r\n]{1,2}(.*?)[\r\n]{0,2}endstream", re.S)
# Content streams contain text operators; image streams do not.
_HAS_TEXT_OPS = re.compile(rb"\bBT\b|\bTj\b|\bTJ\b")
_DCT_RE = re.compile(rb"/DCTDecode\b")
# A kerning shift this large in a TJ array is a word gap, not letter spacing.
_WORD_GAP = -150.0
# Bounds so a large or malformed PDF cannot stall a sweep. A content stream for
# a page of text is a few KB; anything far past that is images or vector art.
MAX_STREAM_BYTES = 1_500_000
MAX_TEXT_CHARS = 400_000
# Matched with .match(buf, pos) so the scanner never slices the buffer. Doing
# `stream[i:]` once per byte copies the remainder every time, which turns a
# large content stream into quadratic work.
_NUM_AT = re.compile(rb"-?\d*\.?\d+")
_OP_AT = re.compile(rb"[A-Za-z'\"*]+")


def _is_ascii_content(raw: bytes, sample: int = 2048) -> bool:
    """True if a stream looks like page-description text rather than image data."""
    head = raw[:sample]
    if not head:
        return False
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head)
    return printable / len(head) >= 0.85


def _decompress(raw: bytes) -> bytes:
    """Inflate a stream, tolerating the leading/trailing whitespace writers add."""
    for candidate in (raw, raw.strip(b"\r\n "), raw.lstrip(b"\r\n ")):
        try:
            return zlib.decompress(candidate)
        except zlib.error:
            continue
    try:  # truncated streams still yield their readable prefix
        return zlib.decompressobj().decompress(raw)
    except zlib.error:
        return b""


def _decode_pdf_string(raw: bytes) -> str:
    """Decode a PDF string's bytes to text (UTF-16BE if marked, else latin-1)."""
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1", "replace")


def _unescape_literal(raw: bytes) -> bytes:
    """Resolve backslash escapes inside a PDF literal string."""
    out = bytearray()
    i = 0
    simple = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12,
              ord("("): 40, ord(")"): 41, ord("\\"): 92}
    while i < len(raw):
        c = raw[i]
        if c != 92:                      # not a backslash
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(raw):
            break
        nxt = raw[i]
        if nxt in simple:
            out.append(simple[nxt])
            i += 1
        elif 48 <= nxt <= 55:            # octal, up to three digits
            digits = bytearray()
            while i < len(raw) and len(digits) < 3 and 48 <= raw[i] <= 55:
                digits.append(raw[i])
                i += 1
            out.append(int(digits, 8) & 0xFF)
        elif nxt in (10, 13):            # line continuation
            i += 1
            if i < len(raw) and raw[i] in (10, 13) and raw[i] != nxt:
                i += 1
        else:
            out.append(nxt)
            i += 1
    return bytes(out)


def _read_literal(data: bytes, start: int) -> tuple[bytes, int]:
    """Read a ``(...)`` string starting at ``start`` (the paren), honoring
    nesting and escapes. Returns (raw_bytes_without_parens, index_after)."""
    depth, i, out = 0, start, bytearray()
    while i < len(data):
        c = data[i]
        if c == 92:                      # backslash escapes the next byte
            out.append(c)
            if i + 1 < len(data):
                out.append(data[i + 1])
            i += 2
            continue
        if c == 40:                      # (
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == 41:                    # )
            depth -= 1
            if depth == 0:
                return bytes(out), i + 1
        out.append(c)
        i += 1
    return bytes(out), i


def content_text(stream: bytes) -> str:
    """Extract the visible text from one decompressed content stream.

    Walks the stream tracking text-showing operators so that ``TJ`` fragments
    are joined correctly and positioning operators become whitespace.
    """
    parts: list[str] = []
    pending: list[str] = []      # strings seen since the last operator
    gaps: list[bool] = []        # whether a word gap preceded each fragment
    i, n = 0, len(stream)

    while i < n:
        c = stream[i]
        if c == 40:                                    # ( literal string
            raw, i = _read_literal(stream, i)
            pending.append(_decode_pdf_string(_unescape_literal(raw)))
            gaps.append(False)
            continue
        if c == 60 and i + 1 < n and stream[i + 1] != 60:   # < hex string
            end = stream.find(b">", i)
            if end == -1:
                break
            hexed = re.sub(rb"[^0-9A-Fa-f]", b"", stream[i + 1:end])
            if len(hexed) % 2:
                hexed += b"0"
            try:
                pending.append(_decode_pdf_string(bytes.fromhex(hexed.decode())))
                gaps.append(False)
            except ValueError:
                pass
            i = end + 1
            continue
        if c == 45 or c == 46 or 48 <= c <= 57:        # a number: kerning in TJ
            m = _NUM_AT.match(stream, i)
            if m:
                try:
                    if float(m.group(0)) <= _WORD_GAP and pending:
                        gaps.append(True)
                        pending.append("")
                except ValueError:
                    pass
                i = m.end()
                continue
        m = _OP_AT.match(stream, i)
        if m:
            op = m.group(0)
            if op in (b"Tj", b"TJ", b"'", b'"'):
                text = "".join(" " + s if gap else s
                               for s, gap in zip(pending, gaps)).strip()
                if text:
                    parts.append(text)
                if op in (b"'", b'"'):
                    parts.append("\n")
                pending, gaps = [], []
            elif op in (b"Td", b"TD", b"T*", b"ET"):
                parts.append("\n")
                pending, gaps = [], []
            elif op == b"BT":
                pending, gaps = [], []
            i = m.end()
            continue
        i += 1

    return "".join(parts)


def _looks_like_text(s: str) -> bool:
    """True if a string is plausibly human text rather than decoded image bytes."""
    if len(s) < 20:
        return False
    letters = sum(ch.isalpha() or ch.isspace() for ch in s)
    return letters / len(s) >= 0.55


def text_builtin(data: bytes) -> str:
    """Extract text with the stdlib parser (no external binaries)."""
    if not data[:5].startswith(b"%PDF"):
        return ""
    chunks: list[str] = []
    for m in _STREAM_RE.finditer(data):
        raw = m.group(1)
        body = _decompress(raw)
        if not body:
            # An uncompressed content stream is legal, but so is a JPEG whose
            # bytes happen to contain "BT" or "Tj". Walking megabytes of image
            # data one byte at a time is what made this hang, so a stream only
            # qualifies if it actually looks like ASCII page content.
            body = raw if (_HAS_TEXT_OPS.search(raw) and _is_ascii_content(raw)) else b""
        if not body or not _HAS_TEXT_OPS.search(body):
            continue                      # image or non-text stream
        piece = content_text(body[:MAX_STREAM_BYTES])
        if _looks_like_text(piece):
            chunks.append(piece)
        if sum(len(c) for c in chunks) > MAX_TEXT_CHARS:
            break
    out = "\n".join(chunks)
    out = re.sub(r"[ \t]+", " ", out)
    return re.sub(r"\n{3,}", "\n\n", out).strip()


def text_pypdf(data: bytes) -> str:
    """Extract text with pypdf, when the library is installed.

    A maintained PDF library beats a hand-written parser: it resolves the page
    tree, filter chains and font encodings properly. Kept optional so the module
    still functions on a machine with nothing installed.
    """
    try:
        import pypdf
    except ImportError:
        return ""
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                reader.decrypt("")          # many PDFs are "encrypted" with no password
            except Exception:               # noqa: BLE001 - unreadable, not fatal
                return ""
        return "\n".join((page.extract_text() or "") for page in reader.pages).strip()
    except Exception:                       # noqa: BLE001 - malformed PDFs are common
        return ""


def text_pdftotext(data: bytes, *, timeout: float = 60.0) -> str:
    """Extract text with poppler's ``pdftotext`` if it is installed.

    Far more accurate than the builtin parser: it resolves font encodings and
    ToUnicode CMaps, so subset fonts come out as real characters instead of
    mojibake.
    """
    if not proc.have("pdftotext"):
        return ""
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    try:
        tmp.write(data)
        tmp.close()
        ran = proc.run(["pdftotext", "-layout", "-enc", "UTF-8", tmp.name, "-"],
                       timeout=timeout)
        return ran.stdout if ran.code == 0 else ""
    finally:
        os.unlink(tmp.name)


def images(data: bytes, *, limit: int = 12) -> list[bytes]:
    """Pull embedded JPEG images out of a PDF.

    ``DCTDecode`` streams are literally JPEG files, so they can be handed
    straight to OCR. This is what makes a scanned document readable at all.
    """
    out: list[bytes] = []
    for m in _STREAM_RE.finditer(data):
        raw = m.group(1)
        start = raw.find(b"\xff\xd8\xff")     # JPEG SOI
        if start != -1 and raw.rfind(b"\xff\xd9") > start:
            out.append(raw[start:raw.rfind(b"\xff\xd9") + 2])
            if len(out) >= limit:
                break
    return out


def text_ocr(data: bytes, *, lang: str = "eng", timeout: float = 120.0,
             limit: int = 6) -> str:
    """OCR a PDF that has no text layer, using tesseract if it is installed.

    Args:
        data: PDF bytes.
        lang: Tesseract language(s), e.g. ``eng``, ``tur``, ``eng+tur``.
        timeout: Per-image timeout.
        limit: Maximum embedded images to OCR.

    Returns:
        Recognized text, or "" when tesseract is unavailable or finds nothing.
    """
    if not proc.have("tesseract"):
        return ""

    # Rendering whole pages with pdftoppm beats pulling embedded images out:
    # a scanned PDF may store its page as Flate-compressed raw samples, or as
    # several tiles, neither of which is a file you can hand to an OCR engine.
    # Falling back to embedded JPEGs keeps this working without poppler.
    page_files: list[str] = []
    tmpdir = tempfile.mkdtemp(prefix="osint-pdf-")
    try:
        if proc.have("pdftoppm"):
            src = os.path.join(tmpdir, "in.pdf")
            with open(src, "wb") as fh:
                fh.write(data)
            ran = proc.run(["pdftoppm", "-r", "200", "-png", "-l", str(limit),
                            src, os.path.join(tmpdir, "page")], timeout=timeout)
            if ran.code == 0:
                page_files = sorted(
                    os.path.join(tmpdir, f) for f in os.listdir(tmpdir)
                    if f.startswith("page") and f.endswith(".png"))
        if not page_files:
            for i, img in enumerate(images(data, limit=limit)):
                path = os.path.join(tmpdir, f"img{i}.jpg")
                with open(path, "wb") as fh:
                    fh.write(img)
                page_files.append(path)
        if not page_files:
            return ""

        log(f"[*] pdf: OCR over {len(page_files)} page image(s) [{lang}]")
        chunks = []
        for path in page_files[:limit]:
            ran = proc.run(["tesseract", path, "stdout", "-l", lang],
                           timeout=timeout)
            if ran.code == 0 and ran.stdout.strip():
                chunks.append(ran.stdout)
        return "\n".join(chunks).strip()
    finally:
        for f in os.listdir(tmpdir):
            try:
                os.unlink(os.path.join(tmpdir, f))
            except OSError:
                pass
        os.rmdir(tmpdir)


def extract(data: bytes, *, ocr: bool = False, lang: str = "eng",
            timeout: float = 60.0) -> dict:
    """Get the best available text out of a PDF, and say how.

    Args:
        data: PDF bytes.
        ocr: Allow the OCR tier for PDFs with no text layer.
        lang: Tesseract language(s) when OCR runs.
        timeout: Per-tool timeout.

    Returns:
        ``{"text","method","has_text_layer","image_count","tools",
        "note"}``. ``method`` is pdftotext/builtin/ocr/none.
    """
    if not data[:5].startswith(b"%PDF"):
        return {"text": "", "method": "none", "has_text_layer": False,
                "image_count": 0, "tools": {}, "note": "not a PDF"}

    try:
        import pypdf  # noqa: F401
        have_pypdf = True
    except ImportError:
        have_pypdf = False
    tools = {"pdftotext": proc.have("pdftotext"), "tesseract": proc.have("tesseract"),
             "pdftoppm": proc.have("pdftoppm"), "pypdf": have_pypdf}
    best, method = "", "none"

    # Best available first; each tier only replaces the previous if it actually
    # produced more text.
    for name, extractor in (("pdftotext", lambda: text_pdftotext(data, timeout=timeout)),
                            ("pypdf", lambda: text_pypdf(data)),
                            ("builtin", lambda: text_builtin(data))):
        if len(best.strip()) >= 40:
            break
        candidate = extractor()
        if len(candidate.strip()) > len(best.strip()):
            best, method = candidate, name

    has_layer = len(best.strip()) >= 40
    img_count = len(images(data))
    note = ""
    if not has_layer:
        if ocr and tools["tesseract"]:
            ocr_text = text_ocr(data, lang=lang, timeout=max(timeout, 120.0))
            if len(ocr_text.strip()) > len(best.strip()):
                best, method = ocr_text, "ocr"
                note = "no text layer; text recovered by OCR (verify before use)"
        else:
            note = ("no text layer — this PDF is a scan or an exported image. "
                    + ("Pass --ocr to read it with tesseract."
                       if tools["tesseract"] else
                       "Install tesseract (apt install tesseract-ocr, plus a "
                       "language pack such as tesseract-ocr-tur) and pass --ocr; "
                       "poppler-utils gives better page rendering."))
    if method == "builtin" and not (tools["pdftotext"] or tools["pypdf"]):
        note = (note + " " if note else "") + (
            "using the stdlib fallback parser; `pip install pypdf` or "
            "`apt install poppler-utils` for better accuracy")

    return {"text": best, "method": method, "has_text_layer": has_layer,
            "image_count": img_count, "tools": tools, "note": note.strip()}


def run(source: str, *, ocr: bool = False, lang: str = "eng",
        region: str = "", timeout: float = 60.0) -> dict:
    """Extract a PDF's text and the contact details in it.

    Args:
        source: A file path or an http(s) URL.
        ocr: Allow the OCR tier.
        lang: Tesseract language(s).
        region: ISO country code for phone/postcode reading.
        timeout: Per-tool timeout.

    Returns:
        The :func:`extract` dict plus ``{"source","emails","phones",
        "addresses","chars"}``.

    Raises:
        ValueError: If the source can't be read.
    """
    if source.startswith(("http://", "https://")):
        from osint import fetch
        r = fetch.get(source, timeout=timeout, retries=1)
        if not r.ok:
            raise ValueError(f"could not fetch {source}: HTTP {r.status}")
        data = r.body
    else:
        try:
            with open(source, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise ValueError(f"could not read {source}: {exc}") from exc

    res = extract(data, ocr=ocr, lang=lang, timeout=timeout)
    from osint import contacts, profile
    found = contacts.run(text=res["text"], region=region)
    emails = sorted({e for e in (x.lower() for x in
                                 profile._EMAIL_RE.findall(res["text"]))
                     if profile._plausible_email(e)})
    return {**res, "source": source, "chars": len(res["text"]),
            "emails": emails, "phones": found["phones"],
            "addresses": found["addresses"]}


def _compact_lines(res: dict, show_text: bool = False) -> list[str]:
    lines = [f"# pdf: {res['source']}",
             f"# method={res['method']}  chars={res['chars']}  "
             f"text_layer={res['has_text_layer']}  images={res['image_count']}"]
    tools = res.get("tools", {})
    lines.append(f"# tools: pypdf={'yes' if tools.get('pypdf') else 'NO'} "
                 f"pdftotext={'yes' if tools.get('pdftotext') else 'NO'} "
                 f"pdftoppm={'yes' if tools.get('pdftoppm') else 'NO'} "
                 f"tesseract={'yes' if tools.get('tesseract') else 'NO'}")
    if res.get("note"):
        lines.append(f"# note: {res['note']}")
    if res["emails"]:
        lines.append(f"## EMAILS ({len(res['emails'])})")
        lines += [f"  {e}" for e in res["emails"]]
    if res["phones"]:
        lines.append(f"## PHONES ({len(res['phones'])})")
        for p in res["phones"]:
            lines.append(f"  {p['e164']:<18} {p['country']}  ({p['confidence']})")
    if res["addresses"]:
        lines.append(f"## ADDRESSES ({len(res['addresses'])})")
        for a in res["addresses"]:
            lines.append(f"  [{a['confidence']}] {a['formatted']}")
    if show_text and res["text"]:
        lines.append("## TEXT")
        lines.append(res["text"])
    elif res["text"]:
        lines.append(f"## TEXT: {res['chars']} chars extracted (pass --text to print it)")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint.pdf",
        description="Extract text and contact details from a PDF (with optional OCR).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python -m osint.pdf cv.pdf\n"
                "  python -m osint.pdf https://example.com/cv.pdf --region TR\n"
                "  python -m osint.pdf scan.pdf --ocr --lang eng+tur\n"
                "\noptional binaries: poppler-utils (pdftotext), tesseract-ocr\n"),
    )
    p.add_argument("source", nargs="?", help="PDF file path or http(s) URL.")
    p.add_argument("--ocr", action="store_true",
                   help="OCR the pages when the PDF has no text layer (needs tesseract).")
    p.add_argument("--lang", default="eng", help="Tesseract language(s), e.g. eng+tur.")
    p.add_argument("--region", default="", help="ISO code for phone/postcode reading.")
    p.add_argument("--timeout", type=float, default=60.0, help="Timeout (default 60).")
    p.add_argument("--text", action="store_true",
                   help="Print the extracted text as well as the findings.")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.source:
        parser.print_help(sys.stderr)
        return 2
    try:
        res = run(args.source, ocr=args.ocr, lang=args.lang, region=args.region,
                  timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res, show_text=args.text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
