import pytest

from recon import subdomains


def test_parser_has_help_and_optional_domain():
    p = subdomains.build_parser()
    # domain is optional so no-args can show help instead of argparse erroring.
    ns = p.parse_args([])
    assert ns.domain is None


def test_main_no_args_returns_2(capsys):
    assert subdomains.main([]) == 2
    err = capsys.readouterr().err
    assert "usage" in err.lower()


def test_main_bad_domain_returns_1(capsys):
    assert subdomains.main(["not a domain"]) == 1
    assert "not a valid domain" in capsys.readouterr().err


def test_compact_lines_shape():
    res = {
        "domain": "example.com",
        "count": 2,
        "subdomains": ["a.example.com", "b.example.com"],
        "sources": {"crtsh": 0, "certspotter": 2},
        "errors": {"crtsh": "down"},
    }
    lines = subdomains._compact_lines(res, resolved=False)
    assert lines[0].startswith("# example.com  2 subdomains")
    assert any("down" in ln for ln in lines)
    assert "a.example.com" in lines and "b.example.com" in lines


@pytest.mark.network
def test_run_live_smoke():
    res = subdomains.run("example.com", sources=["certspotter"])
    assert res["domain"] == "example.com"
    assert "subdomains" in res
