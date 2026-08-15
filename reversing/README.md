# reversing

Reverse-engineering tools. **Named `reversing`, not `re`** — a top-level `re/`
package would shadow Python's standard-library `re` module and break imports.

Fits here: decompilation, disassembly, firmware carving, gadget finding — things
that turn a binary into something an LLM can reason over (pseudo-C, annotated asm).
The AI reads pseudo-C and assembly well; these tools feed it the raw material.

## Tools

- **[decompile.py](decompile.py)** — decompile a binary to **pseudo-C** via Ghidra
  headless (`analyzeHeadless`, no GUI). Default lists the function map (imports,
  functions, strings); `--function NAME` (name or address) decompiles a target;
  `--all` decompiles everything. Works on stripped/optimized binaries. Requires
  Ghidra on the host — meant to run where Ghidra lives (e.g. the Kali box).

  ```bash
  python -m reversing.decompile ./sample                  # function map
  python -m reversing.decompile ./sample --function main  # pseudo-C for main
  python -m reversing.decompile ./sample --all --json
  ```

  For **packed/obfuscated** binaries (high entropy, few functions, a `UPX` string —
  flag them with [../malware/triage.py](../malware/triage.py)), unpack first
  (`upx -d`, or run in a sandbox and dump) then re-decompile.

  Uses the bundled Ghidra script [ghidra_decompile.java](ghidra_decompile.java)
  (Java, so it needs no PyGhidra/Jython — modern Ghidra disables Python in headless).

- **[disasm.py](disasm.py)** — annotated disassembly. Per-function via `objdump`
  (`--function NAME`, `--all`, `--syntax intel|att`) or a raw code blob via
  `capstone` (`--raw --arch x86-64|arm|arm64|mips|... --base 0xADDR`). The
  ground-truth instructions to complement the decompiler's pseudo-C.

  ```bash
  python -m reversing.disasm ./sample --function main
  python -m reversing.disasm shellcode.bin --raw --arch x86-64 --base 0x1000
  ```

- **[firmware.py](firmware.py)** — scan/unpack firmware images with `binwalk` and
  **triage the contents**: lists embedded signatures; `--extract` carves out
  filesystems (SquashFS/JFFS2/...) and surfaces credentials, keys/certs, configs,
  hardcoded secrets, and the embedded binaries to reverse next. Reuses
  [../recon/secrets_scan.py](../recon/secrets_scan.py) on the extracted tree.

  ```bash
  python -m reversing.firmware firmware.bin
  python -m reversing.firmware firmware.bin --extract --json
  ```

  Requires `binwalk` (+ extractors like `squashfs-tools`, `jefferson`) and
  `objdump` (binutils). `capstone` (pip) is only needed for `disasm --raw`.
