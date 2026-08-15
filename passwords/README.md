# passwords

Credential **analysis** — not cracking.

Fits here: password strength/entropy scoring, policy checks, breach-list lookups
via API (e.g. HIBP k-anonymity range API), analysis of a cracked/leaked set for
patterns an LLM should notice.

Doesn't fit: hashcat/John clones or shipped wordlists. Cracking is done with the
Kali tools already on the box; big wordlists live there and are passed by path.
