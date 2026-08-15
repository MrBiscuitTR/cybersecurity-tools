"""Tiny HTTP helper built on the standard library (no `requests` dependency).

Used by the API-driven recon tools. Provides a GET with sane timeouts, a
browser-ish User-Agent (many free APIs 403 the default urllib UA), automatic
reton on transient errors, and helpers for JSON.

Nothing here writes anything anywhere. Read-only network I/O only.
"""

from __future__ import annotations

import gzip
import http.client
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) recon-tools"
DEFAULT_TIMEOUT = 20.0


@dataclass
class Response:
    """Result of a GET. ``ok`` is True on HTTP 2xx."""

    url: str
    status: int          # HTTP status, or 0 if the request never completed
    body: bytes          # raw response body (empty on failure)
    error: str | None    # short error string, or None on success
    elapsed: float       # seconds

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        """Parse the body as JSON. Raises ValueError on bad JSON."""
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"non-JSON response from {self.url}: {exc}") from exc


def get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    retries: int = 2,
    backoff: float = 1.5,
    accept: str = "*/*",
) -> Response:
    """HTTP GET with retries. Never raises for network/HTTP errors — inspect
    ``Response.ok`` / ``Response.error`` instead, so one dead source can't crash
    a multi-source sweep.

    Args:
        url: Absolute URL to fetch.
        timeout: Per-attempt timeout in seconds.
        headers: Extra request headers (merged over the defaults).
        retries: Number of *additional* attempts after the first (so 2 = 3 tries).
        backoff: Multiplier for the sleep between attempts (attempt n waits
            ``backoff ** n`` seconds). Also honors HTTP 429 by retrying.
        accept: Value for the Accept header.

    Returns:
        A :class:`Response`. On repeated failure, ``status`` is the last HTTP
        code seen (or 0) and ``error`` is set.
    """
    hdrs = {"User-Agent": DEFAULT_UA, "Accept": accept, "Accept-Encoding": "gzip"}
    if headers:
        hdrs.update(headers)

    last_err = "unknown error"
    last_status = 0
    start = time.time()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return Response(url, resp.status, raw, None, time.time() - start)
        except urllib.error.HTTPError as exc:
            last_status, last_err = exc.code, f"HTTP {exc.code}"
            # 429/5xx are worth retrying; 4xx (except 429) are not.
            if exc.code != 429 and exc.code < 500:
                break
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
            # HTTPException covers BadStatusLine etc. from a misbehaving DoH/API
            # endpoint; one flaky provider must never crash the caller.
            last_status, last_err = 0, f"{type(exc).__name__}: {exc}"
        if attempt < retries:
            time.sleep(backoff ** (attempt + 1))
    return Response(url, last_status, b"", last_err, time.time() - start)
