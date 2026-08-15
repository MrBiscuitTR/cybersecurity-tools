# crypto

Ciphers, hashes, and encoding — plus practical crypto attacks.

Fits here: hash identification, classical cipher encode/decode/solve,
base/URL/hex encoding helpers, symmetric file encryption, crypto-flaw exploitation.

## Tools

- **[oracle.py](oracle.py)** — crypto oracle attacks:
  - `ecb-detect` — spot ECB mode from a ciphertext (repeated 16-byte blocks).
  - `padding` — decrypt a CBC ciphertext via a **padding oracle**, no key needed
    (fully automated byte-by-byte attack against any endpoint that reveals
    padding validity). Verified: recovered a 33-byte AES-CBC secret in ~5k queries.

  ```bash
  python -m crypto.oracle ecb-detect --data <hexOrBase64>
  python -m crypto.oracle padding --data <hex> \
      --oracle "https://t/decrypt?ct=CIPHER" --valid-status 200 --encoding hex
  ```
