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

- **[bughunt.py](bughunt.py)** — source-code vulnerability sweep (bug-bounty aide).
  Clones/opens a repo and greps ~60 vuln signatures across languages (command
  injection, SQLi, XSS, SSRF, deserialization, memory-unsafe C, hardcoded secrets,
  …), ranks the leads, and writes them to a scratch notes file. The **methodology
  for turning leads into confirmed bugs** lives in the MCP guide and
  [../docs/METHODOLOGY.md](../docs/METHODOLOGY.md). Needs `ripgrep`. Run only when
  asked to hunt bugs.

  ```bash
  python -m analyze.bughunt https://github.com/org/repo
  python -m analyze.bughunt ./repo --classes sqli,ssrf
  ```
