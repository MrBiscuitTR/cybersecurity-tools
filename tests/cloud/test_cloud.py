from cloud import iam_enum, s3_hunt


def test_candidates_permutations():
    c = s3_hunt._candidates("acme")
    assert "acme" in c and "acme-backup" in c and "backup-acme" in c and "acme-dev" in c


def test_s3_run_with_mock(monkeypatch):
    def fake_check(name, timeout):
        if name == "acme-backup":
            return {"bucket": name, "provider": "s3", "state": "PUBLIC-LISTABLE", "url": "u"}
        if name == "acme":
            return {"bucket": name, "provider": "s3", "state": "exists-private", "url": "u"}
        return None
    monkeypatch.setattr(s3_hunt, "_check_bucket", fake_check)
    res = s3_hunt.run("acme")
    assert len(res["public"]) == 1 and res["public"][0]["bucket"] == "acme-backup"
    # public buckets sort first
    assert res["hits"][0]["state"] == "PUBLIC-LISTABLE"


def test_s3_compact():
    res = {"keyword": "acme", "checked": 5,
           "hits": [{"bucket": "b", "provider": "s3", "state": "PUBLIC-LISTABLE", "url": "u"}],
           "public": [{"bucket": "b"}]}
    lines = s3_hunt._compact_lines(res)
    assert any("[!]" in ln and "PUBLIC-LISTABLE" in ln for ln in lines)


def test_s3_main_no_args(capsys):
    assert s3_hunt.main([]) == 2


def test_iam_enum_no_boto3_or_creds(capsys):
    # On a box without boto3 -> FileNotFoundError -> exit 1; with boto3 but no creds
    # -> ValueError -> exit 1. Either way it must fail cleanly (never crash).
    assert iam_enum.main([]) == 1


def test_iam_compact():
    res = {"identity": {"arn": "arn:x", "account": "1", "user_id": "u"},
           "allowed": [{"action": "s3:list_buckets", "note": "list"}], "denied": ["iam:list_users"]}
    lines = iam_enum._compact_lines(res)
    assert any("s3:list_buckets" in ln for ln in lines)
