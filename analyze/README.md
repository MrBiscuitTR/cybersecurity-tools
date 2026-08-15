# analyze

Higher-altitude tools that synthesize other tools' output into decisions — the
"AI reasoner" layer that bootstraps an autonomous operator.

## Tools

- **[exploit_advisor.py](exploit_advisor.py)** — static triage of a binary that
  produces a **prioritized action plan**: likely vulnerability class, why, and which
  tool in this kit to run next (`decompile` / `pwn_template` / `symbolic` / `bindiff`
  / `disasm`). The "I have a binary — now what?" reasoner. Read-only.

  ```bash
  python -m analyze.exploit_advisor ./vuln
  ```
