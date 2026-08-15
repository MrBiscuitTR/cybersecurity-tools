# Conventions

Every tool in this repo follows the same shape so that both a human and the LLM
operator can predict how to run and read it. Copy [../TEMPLATE.py](../TEMPLATE.py)
when starting a new tool.

## 1. Executable *and* importable

Each module is a standalone script **and** a clean import.

- Real work lives in documented functions that return data (objects/dicts),
  never `print()` from library code.
- A `main(argv=None)` function does argparsing + output.
- Guarded entry point:

  ```python
  if __name__ == "__main__":
      raise SystemExit(main())
  ```

## 2. Help is always available; no-args is friendly

- Every tool wires up `argparse`, so `-h` / `--help` works everywhere.
- If a tool needs arguments and gets none, it prints a short usage hint and
  points at `--help`, then exits non-zero — it does **not** hang or error cryptically.

  ```python
  if not any_required_args_present:
      parser.print_help(sys.stderr)
      return 2
  ```

## 3. Output modes

- `--json` → one JSON object/array, complete, to stdout. Default for AI use.
- Human-readable table/text otherwise.
- Errors and progress go to **stderr**; results go to **stdout**, so piping and
  JSON parsing stay clean.
- Never truncate or paginate. Return everything.

## 4. Documentation (this is the point)

Because an LLM decides when to call these, documentation *is* the interface.

- **Module docstring** at the top of every file: what it does, when to use it,
  what it returns, and — **if it calls any external API** — the endpoint(s),
  whether a key is needed, and known rate limits/outages. Note the flakiness of
  sources like crt.sh and the fallbacks used.
- **Function docstrings**: purpose, args (with types), return shape, raised
  exceptions, and any network/side-effect behavior.
- **`--help` epilog**: 1–3 example invocations.
- State explicitly what a tool will **not** do (e.g. "read-only; never writes to
  the target").

## 5. Dependencies & APIs

- Standard library first. Justify every third-party dependency in
  [../requirements.txt](../requirements.txt).
- List external APIs used at the top of the file. No hardcoded secrets — read
  keys from env vars and document which ones.

## 6. Safety (non-negotiable)

- **No destructive actions on the local machine or targets.** Read-only by
  default; active/loud modes are opt-in flags and still non-destructive.
- Conservative defaults for rate/concurrency; aggressive settings require a flag.
- Wrapping a Kali tool via `subprocess` is fine — capture full stdout/stderr and
  return it. Never shell-interpolate untrusted input; pass argument lists, not
  strings.

## 7. Shared code

Cross-cutting helpers (arg scaffolding, JSON/table output, host/URL validators,
subprocess capture, HTTP session with retries) live in [../common](../common) so
tools stay short and consistent.
