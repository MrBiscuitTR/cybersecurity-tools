"""Enumerate what a set of AWS credentials can do — non-destructively.

Answers "I found an AWS key (via secrets_scan / js_recon / a pcap) — what can it
do?" It confirms the identity (sts:GetCallerIdentity) and then probes a curated list
of READ-ONLY actions (List*/Get*/Describe*) across services, recording which are
allowed. The permitted set is your foothold: readable S3, IAM read (privesc recon),
secrets access, EC2 visibility, etc.

Every probe is read-only — no create/modify/delete is ever attempted. It reveals
capability without changing anything.

Credentials come from the standard boto3 chain (env vars AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY [/ AWS_SESSION_TOKEN], or --profile).

Dependencies: ``boto3`` (pip install boto3). No other setup.

Safety: read-only reconnaissance of an account you are authorized to assess. All
probes are Get/List/Describe. Nothing is written, and nothing runs on any instance.

Usage:
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... python -m cloud.iam_enum
    python -m cloud.iam_enum --profile leaked --json
"""

from __future__ import annotations

import argparse
import sys

from common.output import emit, log

# (service, method, kwargs, capability-note). All read-only.
_PROBES = [
    ("iam", "list_users", {}, "IAM read — enumerate users (privesc recon)"),
    ("iam", "list_roles", {}, "IAM read — enumerate roles"),
    ("iam", "get_account_authorization_details", {}, "IAM read-ALL — full policy dump (high)"),
    ("s3", "list_buckets", {}, "S3 — list all buckets"),
    ("ec2", "describe_instances", {}, "EC2 — see instances (IPs, tags, user-data targets)"),
    ("ec2", "describe_security_groups", {}, "EC2 — security groups"),
    ("ec2", "describe_vpcs", {}, "EC2 — VPCs"),
    ("lambda", "list_functions", {}, "Lambda — list functions (code/env secrets)"),
    ("secretsmanager", "list_secrets", {}, "SecretsManager — list secrets (high)"),
    ("ssm", "describe_parameters", {}, "SSM Parameter Store — list params (often secrets)"),
    ("rds", "describe_db_instances", {}, "RDS — database instances"),
    ("dynamodb", "list_tables", {}, "DynamoDB — list tables"),
    ("sts", "get_caller_identity", {}, "STS — identity (always allowed)"),
    ("cloudtrail", "describe_trails", {}, "CloudTrail — logging visibility"),
    ("kms", "list_keys", {}, "KMS — list keys"),
    ("sns", "list_topics", {}, "SNS — list topics"),
    ("sqs", "list_queues", {}, "SQS — list queues"),
    ("ecr", "describe_repositories", {}, "ECR — container images"),
]


def run(*, profile: str = "", region: str = "us-east-1") -> dict:
    """Confirm identity and probe read-only permissions. Returns identity + allowed."""
    try:
        import boto3
        import botocore.exceptions as be
    except ImportError:
        raise FileNotFoundError("boto3 not installed (pip install boto3)")

    session = boto3.session.Session(profile_name=profile or None, region_name=region)
    try:
        identity = session.client("sts").get_caller_identity()
    except Exception as exc:
        raise ValueError(f"credentials invalid or unusable: {exc}")
    ident = {"account": identity.get("Account"), "arn": identity.get("Arn"),
             "user_id": identity.get("UserId")}

    log(f"[*] identity: {ident['arn']}  — probing {len(_PROBES)} read-only actions ...")
    allowed, denied = [], []
    for service, method, kwargs, note in _PROBES:
        try:
            client = session.client(service)
            getattr(client, method)(**kwargs)
            allowed.append({"action": f"{service}:{method}", "note": note})
        except be.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                denied.append(f"{service}:{method}")
            else:  # e.g. it worked but returned an operational error -> permission exists
                allowed.append({"action": f"{service}:{method}", "note": note + f" ({code})"})
        except Exception:
            denied.append(f"{service}:{method}")
    return {"identity": ident, "allowed": allowed, "denied": denied}


def _compact_lines(res: dict) -> list[str]:
    i = res["identity"]
    lines = [f"# iam_enum: {i['arn']}", f"# account={i['account']}  user_id={i['user_id']}"]
    lines.append(f"## ALLOWED read-only actions ({len(res['allowed'])})")
    lines += [f"  [+] {a['action']}  — {a['note']}" for a in res["allowed"]]
    lines.append(f"# denied: {len(res['denied'])} actions")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud.iam_enum",
        description="Enumerate an AWS identity's permissions (read-only probes).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python -m cloud.iam_enum\n  python -m cloud.iam_enum --profile leaked --json\n")
    p.add_argument("--profile", default="", help="AWS profile name (else env credentials).")
    p.add_argument("--region", default="us-east-1", help="AWS region for probes.")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        res = run(profile=args.profile, region=args.region)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    emit(res, as_json=args.json, lines=_compact_lines(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
