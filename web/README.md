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
