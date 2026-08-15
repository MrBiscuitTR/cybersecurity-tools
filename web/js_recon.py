"""Mine a website's JavaScript for endpoints, secrets, and hidden parameters.

Fetches a page, pulls in its linked + inline scripts, and greps the JavaScript
for the things that matter in recon: API endpoints/paths, leaked credentials
(API keys, tokens, private keys), and interesting parameter/variable names. This
is the LinkFinder + SecretFinder workflow in one call — and JS is exactly the
kind of dense, minified text an LLM reads far faster than a human.

Dependencies: standard library only (urllib). No external API. Fetches the target
page and its scripts.

Safety: read-only. GETs the page and its JavaScript; sends no payloads, writes
nothing. Only run against sites you're authorized to test. NOTE: any secret found
is real — handle it carefully and never commit it.

Usage:
    python -m web.js_recon https://example.com
    python -m web.js_recon https://example.com --json
    python -m web.js_recon https://example.com/app.js --only-secrets
"""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import sys
from urllib.parse import urljoin, urlparse

from common import http
from common.output import emit, log

# --- secret patterns (high-signal; SecretFinder-style) ----------------------
# Each: (label, compiled regex). Ordered most-specific first.
_SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("google-oauth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    ("gcp-service-account", re.compile(r'"type":\s*"service_account"')),
    ("stripe-secret", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")),
    ("mailchimp-key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("firebase-url", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("generic-secret", re.compile(
        r"""(?i)(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token|"""
        r"""client[_-]?secret|bearer)['"]?\s*[:=]\s*['"]([^'"\s]{8,60})['"]""")),
]

# --- endpoint/path extraction (LinkFinder-style, simplified but robust) ------
_ABS_URL = re.compile(r"""https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}""")
_QUOTED_PATH = re.compile(r"""['"](/[a-zA-Z0-9_?&=./,%+\-]{2,120})['"]""")
_FETCH_CALL = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch)|url)\s*"""
                         r"""\(\s*['"]([^'"]{2,200})['"]""")
# Static assets we don't care about as "endpoints".
_ASSET_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map|mp4|webp|avif)"
                        r"(?:\?|$)", re.I)

# Parameter-ish names worth flagging.
_PARAM = re.compile(r"""['"]([a-zA-Z_][a-zA-Z0-9_]{2,40})['"]\s*:""")
# Substring match (no \b): param names use underscores (auth_token, is_admin),
# so word boundaries would miss them.
_INTERESTING_PARAM = re.compile(
    r"(?i)(token|secret|passw|admin|debug|internal|apikey|api_key|api-key|auth|"
    r"session|redirect|callback|jwt|access|refresh|private|role)")

_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.I)
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)


def _fetch_text(url: str, timeout: float) -> str:
    r = http.get(url, timeout=timeout, retries=1)
    return r.text if r.body else ""


def _collect_scripts(page_url: str, html: str, timeout: float,
                     workers: int) -> tuple[list[str], dict[str, str]]:
    """Return (script_urls, {source_label: js_text}) for external + inline scripts."""
    srcs = []
    for m in _SCRIPT_SRC.finditer(html):
        srcs.append(urljoin(page_url, m.group(1)))
    srcs = list(dict.fromkeys(srcs))  # dedup, keep order

    bodies: dict[str, str] = {}
    for i, m in enumerate(_INLINE_SCRIPT.finditer(html)):
        if m.group(1).strip():
            bodies[f"inline#{i}"] = m.group(1)

    def fetch(u):
        return u, _fetch_text(u, timeout)

    if srcs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(srcs))) as pool:
            for u, text in pool.map(fetch, srcs):
                if text:
                    bodies[u] = text
    return srcs, bodies


def _short(src: str) -> str:
    """Shorten a source label (last path segment of a URL) for compact output."""
    if src.startswith("inline#"):
        return src
    p = urlparse(src).path
    return p.rsplit("/", 1)[-1] or src


def _extract_secrets(bodies: dict[str, str]) -> list[dict]:
    out, seen = [], set()
    for src, text in bodies.items():
        for label, rx in _SECRET_PATTERNS:
            for m in rx.finditer(text):
                val = m.group(0)[:120]
                key = (label, val)
                if key not in seen:
                    seen.add(key)
                    out.append({"type": label, "match": val, "source": _short(src)})
    return out


def _extract_endpoints(page_url: str, bodies: dict[str, str]) -> list[str]:
    base = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"
    found: set[str] = set()
    for text in bodies.values():
        for m in _ABS_URL.finditer(text):
            found.add(m.group(0).rstrip("\\\"';,"))
        for rx in (_QUOTED_PATH, _FETCH_CALL):
            for m in rx.finditer(text):
                p = m.group(1)
                if p.startswith(("http://", "https://")):
                    found.add(p)
                elif p.startswith("/"):
                    found.add(p)
    # Drop static-asset noise; keep API-ish paths and URLs.
    cleaned = {e for e in found if not _ASSET_EXT.search(e) and len(e) > 3}
    return sorted(cleaned)


def _extract_params(bodies: dict[str, str]) -> list[str]:
    interesting: set[str] = set()
    for text in bodies.values():
        for m in _PARAM.finditer(text):
            name = m.group(1)
            if _INTERESTING_PARAM.search(name):
                interesting.add(name)
    return sorted(interesting)


def run(target: str, *, timeout: float = 12.0, workers: int = 20) -> dict:
    """Fetch ``target`` and mine its JavaScript.

    ``target`` may be a page URL (scripts are discovered and fetched) or a direct
    .js URL (analyzed on its own).

    Returns {"target","scripts","endpoints","secrets","params","stats"}.
    """
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    log(f"[*] fetching {target} ...")
    body = _fetch_text(target, timeout)
    if target.rstrip("/").endswith(".js"):
        scripts, bodies = [target], {target: body}
    else:
        scripts, bodies = _collect_scripts(target, body, timeout, workers)
        bodies.setdefault("(page)", body)  # also scan the HTML itself
    log(f"[*] mining {len(bodies)} script/document bodies ...")

    secrets = _extract_secrets(bodies)
    endpoints = _extract_endpoints(target, bodies)
    params = _extract_params(bodies)
    return {
        "target": target,
        "scripts": scripts,
        "endpoints": endpoints,
        "secrets": secrets,
        "params": params,
        "stats": {"scripts": len(scripts), "endpoints": len(endpoints),
                  "secrets": len(secrets), "params": len(params)},
    }


def _compact_lines(res: dict, only_secrets: bool) -> list[str]:
    st = res["stats"]
    lines = [f"# js_recon: {res['target']}  "
             f"({st['scripts']} scripts, {st['endpoints']} endpoints, "
             f"{st['secrets']} secrets, {st['params']} params)"]
    if res["secrets"]:
        lines.append("## SECRETS (verify before trusting)")
        lines += [f"[{s['type']}] {s['match']}  (in {s['source']})" for s in res["secrets"]]
    if only_secrets:
        return lines
    if res["scripts"]:
        lines.append("## scripts")
        lines += [f"  {s}" for s in res["scripts"]]
    if res["endpoints"]:
        lines.append("## endpoints")
        lines += [f"  {e}" for e in res["endpoints"]]
    if res["params"]:
        lines.append("## interesting params: " + ", ".join(res["params"]))
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.js_recon",
        description="Mine a site's JavaScript for endpoints, secrets, and parameters.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m web.js_recon https://example.com\n"
            "  python -m web.js_recon https://example.com --json\n"
            "  python -m web.js_recon https://example.com/static/app.js --only-secrets\n"
        ),
    )
    p.add_argument("target", nargs="?", help="Page URL or a direct .js URL.")
    p.add_argument("--only-secrets", action="store_true", help="Only report secrets.")
    p.add_argument("--timeout", type=float, default=12.0, help="Per-request timeout (s).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.target, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res, args.only_secrets))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
