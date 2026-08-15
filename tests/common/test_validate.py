import pytest

from common import validate


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.com", "example.com"),
        ("https://Sub.Example.com:443/path?q=1", "sub.example.com"),
        ("*.example.com", "example.com"),
        ("example.com.", "example.com"),
    ],
)
def test_domain_normalizes(raw, expected):
    assert validate.domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "not a domain", "no-tld", "http://", "..."])
def test_domain_rejects(bad):
    with pytest.raises(ValueError):
        validate.domain(bad)


def test_is_subdomain_of():
    assert validate.is_subdomain_of("a.example.com", "example.com")
    assert validate.is_subdomain_of("example.com", "example.com")
    assert not validate.is_subdomain_of("notexample.com", "example.com")
    assert not validate.is_subdomain_of("a.evil.com", "example.com")


def test_ip():
    assert validate.ip("192.168.0.1") == "192.168.0.1"
    with pytest.raises(ValueError):
        validate.ip("999.1.1.1")
