"""Output helpers tuned for an LLM consumer with a limited context window.

Two goals:
  1. Machine mode (``--json``): one complete JSON document, nothing truncated.
  2. Human/compact mode: the *smallest* rendering that still carries the signal —
     plain lines, no boxes, no color, no decoration. Every token should mean
     something.

Import :func:`emit` from a tool's ``main`` to handle both modes uniformly.
"""

from __future__ import annotations

import json
import sys
from typing import Any

# Force UTF-8 on stdout/stderr. On Windows the console defaults to cp1252, so
# emitting a foreign-language error page, an IDN host, or any non-ASCII byte
# would otherwise raise UnicodeEncodeError mid-result. Results must never crash
# on content. ``errors="replace"`` keeps output flowing even for odd bytes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):  # non-reconfigurable stream (e.g. a pipe wrapper)
        pass


def emit(data: Any, *, as_json: bool, lines: list[str] | None = None) -> None:
    """Write results to stdout in the chosen mode.

    Args:
        data: JSON-serializable object emitted verbatim when ``as_json`` is True.
        as_json: If True, dump ``data`` as compact-but-readable JSON.
        lines: Pre-rendered compact text lines for human mode. If None and not
            JSON, ``data`` is JSON-dumped as a fallback.
    """
    if as_json:
        json.dump(data, sys.stdout, ensure_ascii=False, separators=(",", ":"))
        sys.stdout.write("\n")
    elif lines is not None:
        sys.stdout.write("\n".join(lines) + ("\n" if lines else ""))
    else:
        json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")


def log(*msg: object) -> None:
    """Print progress/diagnostics to stderr (keeps stdout clean for results)."""
    print(*msg, file=sys.stderr, flush=True)


def dedup_sorted(items: object) -> list[str]:
    """Lowercase, strip, drop blanks/dupes, and sort. The canonical way tools
    collapse noisy multi-source results into one compact set."""
    seen = {str(x).strip().lower() for x in items if str(x).strip()}
    return sorted(seen)
