# web

Tools that speak HTTP(S) to web applications.

Fits here: security-header auditing, TLS inspection, cookie checks, endpoint
probing, request analysis.

Doesn't fit: raw socket/port work (see [../network](../network)).

## Tools

- **[tls_audit.py](tls_audit.py)** — audits a host's TLS config and HTTP security
  headers in one call: negotiated version/cipher, which TLS versions are accepted
  (flags deprecated 1.0/1.1), the leaf cert (subject/issuer/SANs/expiry, validity,
  self-signed), security headers (HSTS, CSP, X-Frame-Options, nosniff, …), and
  whether HTTP upgrades to HTTPS. Ranks findings HIGH/MEDIUM/LOW. Read-only.

  ```bash
  python -m web.tls_audit example.com
  python -m web.tls_audit example.com:8443 --json
  ```

  Uses `cryptography` to parse the certificate (so invalid/expired certs still
  report their fields).

- **[js_recon.py](js_recon.py)** — mine a site's JavaScript (linked + inline) for
  API endpoints, leaked secrets (API keys, tokens, private keys), and interesting
  parameter names. LinkFinder + SecretFinder in one call; stdlib-only. Read-only.

  ```bash
  python -m web.js_recon https://example.com
  python -m web.js_recon https://example.com/static/app.js --only-secrets --json
  ```

- **[dirfuzz.py](dirfuzz.py)** — content discovery (dir/file brute force) with
  **soft-404 auto-calibration** so hits are real. Built-in wordlist or `--wordlist`.
- **[ssrf.py](ssrf.py)** — SSRF probe (cloud-metadata/file/internal payloads +
  baseline diff + optional out-of-band `--callback` for blind SSRF).
- **[smuggle.py](smuggle.py)** — HTTP request-smuggling (CL.TE/TE.CL) detector via
  the safe timing method (raw sockets; detection only).

- **[jwt_audit.py](jwt_audit.py)** — decode, audit, verify, forge, and attack JWTs.
  Supports `none, HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA`
  (built on `cryptography` + stdlib, no PyJWT). Auto-attacks: `alg=none`, RS→HS
  confusion, weak-secret cracking. Local crypto only — nothing is sent anywhere.

  ```bash
  python -m web.jwt_audit decode <token>
  python -m web.jwt_audit crack <token> --wordlist rockyou.txt
  python -m web.jwt_audit attack <token> --public-key server.pem --wordlist words.txt
  ```
