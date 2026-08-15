# Scope and intended use

Everything in this repository is written for:

- systems and accounts I own,
- lab/VM environments built for practice,
- CTF challenges,
- engagements where written authorization exists and the target is in scope.

## Rules of thumb

- **Authorization first.** Scope in writing, before any packet leaves the machine.
- **Stay inside the boundary.** No pivoting to hosts outside an agreed scope, even
  when reachable.
- **Be gentle by default.** Tools default to conservative rates/concurrency; loud
  settings require an explicit flag.
- **No destructive defaults.** Nothing writes to or modifies a target unless the
  invocation says so.
- **Keep findings private.** Output may contain credentials or PII; treat
  `data/` and any results directory as sensitive and keep them out of commits.

## Not in this repo

Self-propagating code, botnet/C2 infrastructure, DoS tooling, and anything whose
only purpose is evading detection on systems the operator doesn't control.
