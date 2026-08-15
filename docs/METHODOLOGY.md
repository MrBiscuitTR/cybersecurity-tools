# Operator methodology — how to think, and why to write it down

This is guidance for the AI operator driving these tools. It is not code; it is the
mindset that turns tool output into findings and findings into impact.

## Think like an attacker

- **Follow the data, not the code.** A vulnerability is untrusted input reaching a
  dangerous sink. For every input (HTTP param, filename, env var, packet field,
  deserialized blob), ask: where does it go, and is it validated before it gets
  somewhere dangerous (a query, a command, a buffer, a file path, a URL)?
- **A match is a lead, not a bug.** `bughunt`/grep hits mark *where to look*.
  Open the code, trace the source→sink path, and only call it a bug when you can
  describe the exact input that causes the harm.
- **Understand the business logic and trust boundaries.** Who is allowed to do
  what? Cross a boundary the developer assumed no one would: another user's `id`
  (IDOR), an internal-only endpoint, a state that "can't happen", a step skipped.
- **Chain small things into big things.** A verbose error + a predictable ID + a
  missing auth check = account takeover. A path traversal that reads a config that
  holds a key that unlocks an API. Always ask "what does this *enable*?" Keep a
  running list of primitives you've collected (read here, write there, leak this).
- **Prefer depth over breadth once you smell blood.** Cast a wide net first
  (patterns, recon), but when something looks real, go deep and *prove* it before
  moving on. Bigger, chained vulns beat a pile of low-severity noise.
- **Question assumptions and defaults.** Default creds, debug modes, example keys
  left in, "temporary" endpoints, `TODO: remove before prod`, commented-out checks.
- **Be aware of the environment.** Language/framework idioms (Jinja `|safe`, PHP
  superglobals, Node `child_process`), the deploy (containers, cloud metadata,
  reverse proxies), and where secrets/config live.

## Reason about findings

For each candidate, state to yourself: **source** (where input enters) → **path**
(functions it flows through, transformations, checks) → **sink** (the dangerous
operation) → **precondition** (auth? a specific state?) → **impact** (RCE, data read,
takeover) → **severity**. If you can't fill the path from source to sink, it's not
confirmed — dig or drop it.

## Write it down — every time (this is not optional)

Long engagements overflow the context window; it gets summarized or truncated, and
**anything not written down is gone.** Use the `notes` tool (or the `BUGHUNT_NOTES.md`
scratch file) constantly:

- **Note every finding immediately** — confirmed or just interesting — with: what,
  where (`file:line` / URL), the evidence, severity, and how it might chain.
- **Note the primitives you hold** (creds, tokens, readable paths, leaked values)
  and open questions / next steps.
- **Re-read your notes after any compaction** to recover state before continuing.
- **Keep entries brief but complete** — a stranger (or future-you with no context)
  should understand the finding from the note alone.
- **Skip the genuinely useless.** Don't record noise; record signal.

## Writeups

When asked to report, turn the notes into a writeup per finding: **title,
severity, affected component, description, step-by-step reproduction / PoC,
impact, and remediation.** Order by severity. Be precise and reproducible — a good
writeup lets someone else confirm the bug without guessing.

## Hard rule

Exploitation and any active/intrusive step happen only with explicit user
permission and only against authorized targets. Enumerate and prove safely first;
ask before you pull the trigger.
