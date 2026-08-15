# Vision

## One sentence

A library of small, AI-operated security tools that fill the gaps Kali leaves —
fast enumeration, recon, OSINT, and API-driven tasks — exposed to a local LLM
through an MCP server so the model can do the fiddly parts and keep the intuition.

## The deployment picture

```
   local LLM (the operator)
        │  natural-language intent
        ▼
   MCP server  ──►  these custom tools  ──►  targets / third-party APIs
   (runs on Kali)   +  existing Kali tools (nmap, ffuf, tshark, ...)
```

The model reasons; the tools do deterministic work and hand back complete,
machine-readable output. The Kali box already has the mainstream toolkit. This
repo adds the things Kali does *not* do easily.

## What belongs here

- **Fast enumeration & recon** — subdomain discovery, DNS/record sweeps, cert
  transparency, takeover detection.
- **OSINT & info gathering** — anything that is mostly API calls and correlation.
- **API-driven tasks** — things that need calling crt.sh (and its flaky
  mirrors/fallbacks), CT logs, WHOIS/RDAP, favicon-hash lookups, etc.
- **Automation beyond mainstream flags** — chaining steps (enum → resolve →
  fingerprint → flag) that would otherwise be a pile of shell glue.
- **AI-leverage tasks** — wrap an existing tool, capture its *entire* output, and
  return it raw for the model to read: pcap/cap dumps, disassembly, static
  analysis, crypto inspection, header/import tables.

## What does NOT belong here

- **Kali clones.** No from-scratch port scanner competing with nmap, no
  hashcat/John reimplementation, no ffuf clone. If Kali already does it well with
  memorable flags, call Kali.
- **Shipped wordlists / signature dumps.** `data/` holds tiny fixtures only; big
  lists live on the Kali box (`/usr/share/...`) and are passed in by path.
- **Anything destructive.** See the hard rule below.

## Hard rules

- **No destructive actions, ever — on this PC or on targets.** No writing to,
  modifying, or deleting anything on the local machine outside the repo's own
  output. No destructive defaults against targets. Loud/active behavior is
  opt-in via an explicit flag and still stops short of damage.
- **Authorized use only.** See [scope.md](scope.md).
- **Minimal dependencies.** Prefer the standard library. Every third-party import
  must earn its place, and every external **API** used must be noted at the top
  of the file (endpoint, auth needs, rate limits).

## Design for an AI operator, not a human at a terminal

The consumer is an LLM that reads long outputs and processes everything at once.
Optimize for that:

- **Dump complete output, don't paginate or truncate.** No `less`, no "N more
  results". The model wants the whole thing.
- **Return structured data.** Prefer `--json` for machine parsing; keep a human
  table mode too. A function used as an import returns objects, not printed text.
- **No interactivity.** No prompts, no TTY tricks, no color-as-meaning. Runs
  headless and deterministic.
- **Explain in docstrings what a human would infer.** The model relies on the
  docstring/`--help` to know when and how to use a tool. Say what it does, what
  it needs, what it returns, which APIs it hits, and what it will *not* do.

### Where the AI is strong (lean into these)

Reading assembly and producing/reading pseudo-C; spotting crypto flaws; basic
bug pattern-matching (`gets`, overflow-shaped loops, unchecked pointers,
format-string sinks); static analysis and malware triage; reading pcap/tshark
output without the eyesore; and knowing exactly which `curl` flags, data, and
endpoint to hit after enumeration. Tools here should feed those strengths raw
material, not pre-chew it into a lossy summary.
