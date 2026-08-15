import io
import json
from contextlib import redirect_stdout

from common import output


def test_dedup_sorted():
    assert output.dedup_sorted(["B", "a", "a", " ", "A"]) == ["a", "b"]


def test_emit_json_is_complete_and_parseable():
    buf = io.StringIO()
    data = {"count": 2, "subdomains": ["a.example.com", "b.example.com"]}
    with redirect_stdout(buf):
        output.emit(data, as_json=True)
    assert json.loads(buf.getvalue()) == data


def test_emit_lines():
    buf = io.StringIO()
    with redirect_stdout(buf):
        output.emit({}, as_json=False, lines=["one", "two"])
    assert buf.getvalue() == "one\ntwo\n"
