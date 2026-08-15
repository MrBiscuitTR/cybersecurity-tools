# common

Shared helpers imported by the tool packages, plus two general-purpose tools the
autonomous operator uses everywhere.

Helpers: HTTP (stdlib), DNS-over-HTTPS, JSON/compact output, validators
(IP/host/URL/domain), subprocess capture.

## Tools

- **[safe_bash.py](safe_bash.py)** — policy-gated shell runner. Runs read-only
  recon/analysis commands (rg, grep, find, git, curl, objdump, python3, pipes…)
  but **blocks destructive/host-changing commands** (rm/mv/dd/chmod/sudo/mkfs/
  package installs/…) — they are never executed. Output is capped for context.
  The backbone of manual investigation.

  ```bash
  python -m common.safe_bash "rg -n gets src/"
  ```

- **[notes.py](notes.py)** — persistent scratch notebook (`append`/`read`/`clear`)
  so findings survive context compaction. Take notes constantly; re-read after a
  compaction. See [../docs/METHODOLOGY.md](../docs/METHODOLOGY.md).

  ```bash
  python -m common.notes append "SQLi confirmed in /search q= (union)"
  ```
