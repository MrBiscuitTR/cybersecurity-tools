# cloud

Cloud-focused offensive tooling — where a lot of modern attack surface lives.

## Tools

- **[s3_hunt.py](s3_hunt.py)** — hunt public S3/GCS/Azure Blob buckets from a
  keyword (permutations) or check one exact bucket. Flags PUBLIC-LISTABLE buckets.
  Anonymous HTTP, no keys. Read-only (never downloads/writes).

  ```bash
  python -m cloud.s3_hunt acmecorp
  python -m cloud.s3_hunt --bucket flaws.cloud
  ```

- **[iam_enum.py](iam_enum.py)** — given AWS credentials (env or `--profile`),
  enumerate what they can do by probing read-only actions across services. Answers
  "I found this key — what can it do?". Every probe is Get/List/Describe;
  **nothing is created/modified/deleted**. Needs `boto3`.

  ```bash
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... python -m cloud.iam_enum --json
  ```

  Pairs with [../recon/secrets_scan.py](../recon/secrets_scan.py) /
  [../web/js_recon.py](../web/js_recon.py): find a key, then see its reach.
