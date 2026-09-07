"""Browser-realistic HTTP + multi-source fan-out, shared by every osint tool.

``common.http`` is deliberately tiny and honest about being a tool ("recon-tools"
in the UA). OSINT sources are hostile to that: consumer platforms fingerprint the
User-Agent, require a full browser header set, set cookies on a redirect hop, and
serve a soft block page instead of an error. So this module adds, on top of the
stdlib:

  * a pool of current, realistic browser User-Agents, rotated per attempt, with
    the matching ``Sec-CH-UA`` / ``Sec-Fetch-*`` / ``Accept-Language`` headers a
    real Chrome or Firefox sends (a mismatched set is itself a bot signal);
  * redirect following with the full chain recorded, plus a per-request cookie
    jar so consent/interstitial redirects resolve like they do in a browser;
  * the response body kept even on 4xx/5xx — block pages and soft-404s are
    evidence, and text-marker checks need them;
  * retry with UA rotation and jittered backoff specifically on 403/429, the
    codes that mean "we think you're a bot" rather than "this doesn't exist";
  * :func:`gather`, the fan-out primitive: run many independent sources
    concurrently, keep whatever answers, and report which ones failed — the same
    design as ``recon.subdomains``' 8 sources. No single API is ever a
    dependency; every capability in this package has fallbacks.
  * :func:`render`, an OPTIONAL headless-browser escape hatch for JS-only pages.
    Uses Playwright if it is installed; otherwise returns a clear, actionable
    error instead of pretending. Nothing in this package requires it.

Safety: read-only. Issues ordinary GETs for public pages, follows redirects, and
stores cookies for the lifetime of one request. No login, no credential replay,
no captcha solving, no write of any kind.
"""

from __future__ import annotations

import concurrent.futures
import gzip
import http.client
import http.cookiejar
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# Realistic, current desktop browsers. Each entry carries the client hints that
# must agree with the UA string — sending Chrome's Sec-CH-UA with a Firefox UA is
# a louder bot signal than sending none at all.
_BROWSERS: list[dict[str, str]] = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        "platform": '"Windows"',
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        "platform": '"macOS"',
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="139", "Not=A?Brand";v="24", "Google Chrome";v="139"',
        "platform": '"Linux"',
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) "
              "Gecko/20100101 Firefox/130.0",
        "sec_ch_ua": "",  # Firefox does not send client hints
        "platform": "",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "sec_ch_ua": "",
        "platform": "",
    },
]

DEFAULT_TIMEOUT = 20.0
# Only encodings the stdlib can actually decode. Advertising `br` without a
# brotli decoder yields unreadable bytes, which looks like a broken source.
_ACCEPT_ENCODING = "gzip, deflate"
_HTML_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8")


def browser_headers(
    *,
    browser: dict[str, str] | None = None,
    accept: str = _HTML_ACCEPT,
    referer: str = "",
    lang: str = "en-US,en;q=0.9",
) -> dict[str, str]:
    """Build a complete, self-consistent browser header set.

    Args:
        browser: An entry from the internal pool; random if None.
        accept: Accept header (use ``application/json`` for API endpoints).
        referer: Optional Referer — some sites 403 a "typed URL" but allow a
            click-through from their own domain.
        lang: Accept-Language.

    Returns:
        A header dict suitable for :func:`get`.
    """
    b = browser or random.choice(_BROWSERS)
    h = {
        "User-Agent": b["ua"],
        "Accept": accept,
        "Accept-Language": lang,
        "Accept-Encoding": _ACCEPT_ENCODING,
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site" if referer else "none",
        "Sec-Fetch-User": "?1",
        "Connection": "keep-alive",
    }
    if b.get("sec_ch_ua"):
        h["Sec-CH-UA"] = b["sec_ch_ua"]
        h["Sec-CH-UA-Mobile"] = "?0"
        h["Sec-CH-UA-Platform"] = b["platform"]
    if referer:
        h["Referer"] = referer
    if "json" in accept:
        # An XHR-looking request should not claim to be a top-level navigation.
        h.update({"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                  "X-Requested-With": "XMLHttpRequest"})
    return h


@dataclass
class Response:
    """Result of a fetch. ``ok`` is True on HTTP 2xx.

    Unlike ``common.http.Response`` the body is populated even for error codes,
    because block pages and soft-404s carry the signal we need.
    """

    url: str
    final_url: str
    status: int
    body: bytes
    error: str | None
    elapsed: float
    redirects: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    ua: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def blocked(self) -> bool:
        """True if this looks like an anti-bot block rather than a real answer."""
        if self.status in (401, 403, 429):
            return True
        if self.status == 200 and self.body:
            head = self.body[:4000].lower()
            return any(m in head for m in (
                b"client challenge", b"just a moment", b"cf-browser-verification",
                b"attention required! | cloudflare", b"px-captcha", b"captcha-delivery",
                b"enable javascript and cookies to continue", b"are you a robot",
            ))
        return False

    @property
    def text(self) -> str:
        """Body decoded with the charset from the headers, then a meta tag, then
        UTF-8 with replacement. Never raises."""
        ctype = self.headers.get("content-type", "")
        m = re.search(r"charset=([\w\-]+)", ctype, re.I)
        enc = m.group(1) if m else ""
        if not enc:
            m = re.search(rb'charset=["\']?([\w\-]+)', self.body[:2048], re.I)
            enc = m.group(1).decode("ascii", "ignore") if m else "utf-8"
        try:
            return self.body.decode(enc, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        """Parse the body as JSON. Raises ValueError on bad JSON."""
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"non-JSON response from {self.final_url}: {exc}") from exc


class _ChainRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects like a browser while recording every hop."""

    def __init__(self) -> None:
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _decompress(raw: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if enc == "gzip":
            return gzip.decompress(raw)
        if enc == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)  # raw deflate
    except (OSError, zlib.error):
        return raw  # served a wrong Content-Encoding; use bytes as-is
    return raw


def get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = 2,
    headers: dict[str, str] | None = None,
    accept: str = _HTML_ACCEPT,
    referer: str = "",
    follow_redirects: bool = True,
    rotate_ua: bool = True,
    data: bytes | None = None,
) -> Response:
    """Browser-realistic GET (or POST when ``data`` is given).

    Never raises for network/HTTP errors — inspect ``Response.ok`` /
    ``.blocked`` / ``.error``. Retries on 403/429/5xx and transport errors,
    rotating the User-Agent each attempt, because a different browser identity is
    often all that separates a block from a 200.

    Args:
        url: Absolute URL.
        timeout: Per-attempt timeout in seconds.
        retries: Additional attempts after the first.
        headers: Extra headers merged over the generated browser set.
        accept: Accept header; pass ``application/json`` for APIs.
        referer: Optional Referer header.
        follow_redirects: Follow 3xx (default True, like a browser).
        rotate_ua: Use a different browser identity on each retry.
        data: If set, sends a POST with this body.

    Returns:
        A :class:`Response`, with the body preserved even on error codes.
    """
    start = time.time()
    last_err, last_status, last_body, last_hdrs = "unknown error", 0, b"", {}
    last_ua, chain = "", []
    browser = random.choice(_BROWSERS)

    for attempt in range(retries + 1):
        if rotate_ua and attempt:
            browser = random.choice(_BROWSERS)
        hdrs = browser_headers(browser=browser, accept=accept, referer=referer)
        if headers:
            hdrs.update(headers)
        last_ua = hdrs["User-Agent"]

        redirector = _ChainRedirectHandler()
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if follow_redirects:
            handlers.append(redirector)
        else:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)

        try:
            req = urllib.request.Request(url, headers=hdrs, data=data)
            with opener.open(req, timeout=timeout) as resp:
                raw = _decompress(resp.read(), resp.headers.get("Content-Encoding", ""))
                rh = {k.lower(): v for k, v in resp.headers.items()}
                r = Response(url, resp.geturl(), resp.status, raw, None,
                             time.time() - start, redirector.chain, rh, last_ua)
                # A 200 that is really a bot wall is worth one more identity.
                if r.blocked and attempt < retries:
                    last_status, last_body, last_hdrs = r.status, r.body, r.headers
                    last_err, chain = "anti-bot page", r.redirects
                    time.sleep(random.uniform(0.6, 1.6) * (attempt + 1))
                    continue
                return r
        except urllib.error.HTTPError as exc:
            # HTTPError is itself a file-like response: keep the body.
            try:
                last_body = _decompress(exc.read(), exc.headers.get("Content-Encoding", ""))
                last_hdrs = {k.lower(): v for k, v in exc.headers.items()}
            except Exception:  # noqa: BLE001 - body is best-effort only
                last_body, last_hdrs = b"", {}
            last_status, last_err = exc.code, f"HTTP {exc.code}"
            chain = redirector.chain
            # 403/429 = "you look like a bot" -> worth another identity.
            # Other 4xx are real answers (404 = no such user); don't waste a retry.
            if exc.code not in (403, 429) and exc.code < 500:
                break
        except (urllib.error.URLError, http.client.HTTPException,
                TimeoutError, OSError, ValueError) as exc:
            last_status, last_err = 0, f"{type(exc).__name__}: {exc}"
            last_body, chain = b"", redirector.chain
        if attempt < retries:
            time.sleep(random.uniform(0.5, 1.5) * (attempt + 1))

    return Response(url, chain[-1] if chain else url, last_status, last_body,
                    last_err, time.time() - start, chain, last_hdrs, last_ua)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn redirects into plain responses instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def get_json(url: str, **kw: Any) -> tuple[Any, Response]:
    """GET a JSON API. Returns ``(parsed_or_None, response)``; never raises."""
    kw.setdefault("accept", "application/json, text/plain, */*")
    r = get(url, **kw)
    if not r.ok:
        return None, r
    try:
        return r.json(), r
    except ValueError:
        return None, r


def get_first(urls: Iterable[str], **kw: Any) -> Response:
    """Try mirrors/endpoints in order, returning the first non-blocked 2xx.

    For a capability served by several interchangeable hosts (public SearXNG
    instances, Nitter mirrors, API mirrors). If all fail, returns the last
    response so the caller can still see why.

    Args:
        urls: Candidate URLs, best first.
        **kw: Passed through to :func:`get`.
    """
    last = Response("", "", 0, b"", "no urls given", 0.0)
    for u in urls:
        last = get(u, **kw)
        if last.ok and not last.blocked:
            return last
    return last


def gather(
    sources: dict[str, Callable[[], Any]],
    *,
    workers: int = 8,
    timeout: float = 45.0,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Run independent sources concurrently; keep what works, note what doesn't.

    The redundancy primitive behind every tool in this package. Each callable is
    one source. A source that raises, times out, or returns nothing is recorded
    as down rather than being allowed to fail the whole query — which is the
    point of querying many sources for the same fact.

    Args:
        sources: ``{source_name: zero-arg callable}``.
        workers: Max concurrent sources.
        timeout: Overall wall-clock budget in seconds.

    Returns:
        ``(results, down)`` — ``results`` maps source name to its return value
        for sources that produced a truthy result; ``down`` maps source name to a
        short reason for those that didn't.
    """
    results: dict[str, Any] = {}
    down: dict[str, str] = {}
    if not sources:
        return results, down

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(workers, len(sources))) as pool:
        futures = {pool.submit(fn): name for name, fn in sources.items()}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=timeout):
                name = futures[fut]
                try:
                    val = fut.result()
                except Exception as exc:  # noqa: BLE001 - one bad source must not win
                    down[name] = f"{type(exc).__name__}: {exc}"
                    continue
                if val:
                    results[name] = val
                else:
                    down[name] = "no results"
        except concurrent.futures.TimeoutError:
            for fut, name in futures.items():
                if name not in results and name not in down:
                    down[name] = "timed out"
                    fut.cancel()
    return results, down


def split_down(down: dict[str, str]) -> tuple[list[str], list[str]]:
    """Split :func:`gather`'s ``down`` map into (no_results, failed).

    "The register answered and has nothing on this person" and "the register
    never answered" mean completely different things to whoever reads the
    output; collapsing both into "down" misleads.

    Returns:
        ``(sources_with_no_results, sources_that_failed)``, both sorted.
    """
    empty = sorted(k for k, v in down.items() if v == "no results")
    failed = sorted(k for k, v in down.items() if v != "no results")
    return empty, failed


def render(url: str, *, timeout: float = 25.0, wait_selector: str = "") -> dict:
    """Render a JavaScript-only page in a headless browser (OPTIONAL feature).

    Nothing in this package needs this: every source is chosen to work over plain
    HTTP. Reach for it only when a target page genuinely builds its content in
    JS and no API alternative exists.

    Requires Playwright, which is NOT in requirements.txt because it ships a
    ~150MB browser:

        pip install playwright && playwright install chromium

    Args:
        url: Page to render.
        timeout: Seconds to wait for load.
        wait_selector: Optional CSS selector to wait for before snapshotting.

    Returns:
        ``{"url", "status", "html", "title", "rendered": True}`` on success, or
        ``{"error": ..., "rendered": False}`` if Playwright is unavailable or the
        page failed. Never raises.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return {"url": url, "rendered": False,
                "error": "playwright not installed — "
                         "`pip install playwright && playwright install chromium`"}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(
                user_agent=random.choice(_BROWSERS)["ua"],
                locale="en-US", viewport={"width": 1440, "height": 900})
            page = ctx.new_page()
            resp = page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            if wait_selector:
                page.wait_for_selector(wait_selector, timeout=timeout * 1000)
            out = {"url": url, "status": resp.status if resp else 0,
                   "html": page.content(), "title": page.title(), "rendered": True}
            browser.close()
            return out
    except Exception as exc:  # noqa: BLE001 - optional path, degrade cleanly
        return {"url": url, "rendered": False, "error": f"{type(exc).__name__}: {exc}"}
