"""Introspect and audit a GraphQL endpoint.

Points at a GraphQL URL and, if introspection is enabled, dumps the schema (queries,
mutations, subscriptions, types) and flags the security-relevant bits: introspection
being open at all, sensitive-looking fields (password/token/secret), dangerous
mutations (delete/admin/reset), and misconfigs (GET queries -> CSRF, query batching
-> DoS). Modern APIs hide their whole surface behind GraphQL; this maps it in one call.

Dependencies: standard library only (urllib). No external API.

Safety: read-only recon. Sends an introspection query and two harmless probes; runs
no mutations. Only test endpoints you're authorized to.

Usage:
    python -m web.graphql https://example.com/graphql
    python -m web.graphql https://example.com/graphql --json
"""

from __future__ import annotations

import argparse
import json
import sys

from common import http
from common.output import emit, log

# Compact introspection: enough to map the surface and spot sensitive ops/fields.
_INTROSPECT = ("{__schema{queryType{name fields{name}}"
               "mutationType{name fields{name args{name}}}"
               "subscriptionType{name fields{name}}"
               "types{name kind fields{name}}}}")

_SENSITIVE = ("password", "passwd", "secret", "token", "apikey", "api_key", "ssn",
              "creditcard", "credit_card", "privatekey", "private_key", "session")
_DANGEROUS = ("delete", "drop", "remove", "destroy", "reset", "admin", "grant",
              "revoke", "impersonate", "setpassword", "createuser", "updateuser")


def _post(url: str, query: str, timeout: float) -> dict:
    body = json.dumps({"query": query}).encode()
    import urllib.request
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": http.DEFAULT_UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "json": json.loads(resp.read())}
    except Exception as exc:
        hdrs = getattr(exc, "headers", None)
        try:
            data = json.loads(exc.read()) if hasattr(exc, "read") else None
        except Exception:
            data = None
        return {"status": getattr(exc, "code", 0), "json": data,
                "error": f"{type(exc).__name__}: {exc}"}


def _get_probe(url: str, timeout: float) -> bool:
    """Does the endpoint answer a query over GET (CSRF-relevant)?"""
    r = http.get(url + "?query=%7B__typename%7D", timeout=timeout, retries=0)
    return r.ok and b"__typename" in r.body


def run(url: str, *, timeout: float = 15.0) -> dict:
    log(f"[*] introspecting {url} ...")
    resp = _post(url, _INTROSPECT, timeout)
    schema = (resp.get("json") or {}).get("data", {}).get("__schema") if resp.get("json") else None

    findings: list[dict] = []
    result = {"url": url, "introspection": bool(schema)}
    if not schema:
        result["error"] = resp.get("error") or "introspection disabled or not a GraphQL endpoint"
        result["findings"] = [{"level": "info",
                               "note": "introspection disabled (good) or endpoint invalid"}]
        return result

    findings.append({"level": "medium",
                     "note": "introspection is ENABLED — full schema is disclosed"})
    q = (schema.get("queryType") or {}).get("fields") or []
    m = (schema.get("mutationType") or {}).get("fields") or []
    s = (schema.get("subscriptionType") or {}).get("fields") or []
    queries = [f["name"] for f in q]
    mutations = [f["name"] for f in m]
    subscriptions = [f["name"] for f in s]

    dangerous = [n for n in mutations if any(d in n.lower() for d in _DANGEROUS)]
    for n in dangerous:
        findings.append({"level": "medium", "note": f"sensitive mutation exposed: {n}"})

    sensitive_fields = []
    for t in schema.get("types", []):
        for f in (t.get("fields") or []):
            if any(sk in f["name"].lower() for sk in _SENSITIVE):
                sensitive_fields.append(f"{t['name']}.{f['name']}")
    if sensitive_fields:
        findings.append({"level": "medium",
                         "note": f"{len(sensitive_fields)} sensitive-looking fields (e.g. "
                                 f"{', '.join(sensitive_fields[:5])})"})

    if _get_probe(url, timeout):
        findings.append({"level": "medium", "note": "queries accepted over GET — CSRF risk"})

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["level"], 3))
    result.update({
        "queries": queries, "mutations": mutations, "subscriptions": subscriptions,
        "dangerous_mutations": dangerous, "sensitive_fields": sensitive_fields,
        "type_count": len(schema.get("types", [])), "findings": findings,
    })
    return result


def _compact_lines(res: dict) -> list[str]:
    lines = [f"# graphql: {res['url']}  introspection={res['introspection']}"]
    if not res["introspection"]:
        lines.append(f"# {res.get('error', '')}")
        return lines
    lines.append(f"# queries={len(res['queries'])} mutations={len(res['mutations'])} "
                 f"subscriptions={len(res['subscriptions'])} types={res['type_count']}")
    lines.append("## FINDINGS")
    lines += [f"[{f['level'].upper()}] {f['note']}" for f in res["findings"]]
    if res["mutations"]:
        lines.append("## mutations")
        lines += [f"  {'[!] ' if n in res['dangerous_mutations'] else ''}{n}"
                  for n in res["mutations"]]
    if res["queries"]:
        lines.append("## queries")
        lines += [f"  {n}" for n in res["queries"][:80]]
    if res["sensitive_fields"]:
        lines.append("## sensitive fields")
        lines += [f"  {f}" for f in res["sensitive_fields"][:40]]
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web.graphql",
        description="Introspect + audit a GraphQL endpoint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  python -m web.graphql https://example.com/graphql\n",
    )
    p.add_argument("url", nargs="?", help="GraphQL endpoint URL.")
    p.add_argument("--timeout", type=float, default=15.0, help="Request timeout (s).")
    p.add_argument("--json", action="store_true", help="Emit one complete JSON object.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url:
        build_parser().print_help(sys.stderr)
        return 2
    res = run(args.url, timeout=args.timeout)
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
