import zlib

import pytest

from osint import pdf


def _pdf(content_stream: bytes, *, compress: bool = True) -> bytes:
    body = zlib.compress(content_stream) if compress else content_stream
    return b"%PDF-1.4\n1 0 obj\nstream\n" + body + b"\nendstream\nendobj\n%%EOF"


def test_simple_literal_string():
    assert "Hello world" in pdf.text_builtin(
        _pdf(b"BT /F1 12 Tf (Hello world, this is a sentence of text) Tj ET"))


def test_tj_array_fragments_are_joined_without_spaces():
    """Kerning splits words into fragments; joining them with spaces yields
    'r ec ogniz es' and shreds any email address on the page."""
    stream = (b"BT [(recogniz) -12 (es exempl) -8 (ary achievement in the) -15"
              b" ( document body)] TJ ET")
    out = pdf.text_builtin(_pdf(stream))
    assert "recognizes" in out
    assert "r ec ogniz es" not in out


def test_large_kerning_becomes_a_word_gap():
    stream = b"BT [(some words here and) -400 (another word follows now)] TJ ET"
    out = pdf.text_builtin(_pdf(stream))
    assert "and another" in out


def test_email_survives_fragmentation():
    stream = (b"BT [(cont) -10 (act@cagan) -12 (calidag.com is the address here)]"
              b" TJ ET")
    assert "contact@cagancalidag.com" in pdf.text_builtin(_pdf(stream))


def test_hex_strings_are_decoded():
    # "Hello there, this is hex encoded text" in hex.
    hexed = b"48656c6c6f2074686572652c2074686973206973206865782074657874"
    assert "Hello there" in pdf.text_builtin(_pdf(b"BT <" + hexed + b"> Tj ET"))


def test_octal_escapes_are_resolved():
    out = pdf.text_builtin(_pdf(rb"BT (caf\351 society meets here every day) Tj ET"))
    assert "caf" in out and "society" in out


def test_uncompressed_content_stream():
    assert "plain text" in pdf.text_builtin(
        _pdf(b"BT (this is plain text in an uncompressed stream) Tj ET",
             compress=False))


def test_image_stream_is_not_parsed_as_text():
    """JPEG bytes contain sequences that look like PDF literals; parsing them
    produced pages of garbage."""
    noise = bytes(range(256)) * 40
    out = pdf.text_builtin(_pdf(b"BT " + noise + b" Tj ET", compress=False))
    assert out == "" or out.isprintable()


def test_non_pdf_returns_nothing():
    assert pdf.text_builtin(b"<html>not a pdf</html>") == ""


def test_extract_reports_missing_text_layer():
    res = pdf.extract(_pdf(b"\x00\x01\x02" * 500, compress=False))
    assert res["has_text_layer"] is False
    assert res["method"] in ("none", "builtin", "pdftotext")
    assert "no text layer" in res["note"] or res["note"] == "" or "install" in res["note"].lower()


def test_extract_rejects_non_pdf():
    res = pdf.extract(b"just some bytes")
    assert res["method"] == "none" and res["note"] == "not a PDF"


def test_images_finds_embedded_jpeg():
    jpeg = b"\xff\xd8\xff" + b"\x00" * 50 + b"\xff\xd9"
    assert pdf.images(_pdf(jpeg, compress=False)) == [jpeg]


def test_ocr_without_tesseract_returns_empty(monkeypatch):
    monkeypatch.setattr(pdf.proc, "have", lambda b: False)
    assert pdf.text_ocr(_pdf(b"x", compress=False)) == ""


def test_main_no_args_returns_2():
    assert pdf.main([]) == 2


def test_run_rejects_missing_file():
    with pytest.raises(ValueError):
        pdf.run("/no/such/file.pdf")
