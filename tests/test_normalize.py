"""Tests for observable normalisation."""

from threat_intel_enrichment.normalize import (
    NormalizedEntity,
    classify_entity,
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_url,
)


def test_normalize_ipv4() -> None:
    assert normalize_ip(" 192.0.2.10 ") == ("ipv4", "192.0.2.10")


def test_normalize_ipv6() -> None:
    assert normalize_ip("2001:0db8:0000:0000:0000:ff00:0042:8329") == (
        "ipv6",
        "2001:db8::ff00:42:8329",
    )


def test_reject_invalid_ip() -> None:
    assert normalize_ip("999.999.999.999") is None


def test_normalize_domain_case_and_trailing_dot() -> None:
    assert normalize_domain("Example.COM.") == "example.com"


def test_preserve_subdomain() -> None:
    assert normalize_domain("Login.Example.com") == "login.example.com"


def test_normalize_international_domain() -> None:
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"


def test_reject_single_label_domain() -> None:
    assert normalize_domain("localhost") is None


def test_reject_invalid_domain_label() -> None:
    assert normalize_domain("-invalid.example.com") is None


def test_normalize_http_url() -> None:
    assert (
        normalize_url("HTTP://Example.COM:80/login?user=test#section")
        == "http://example.com/login?user=test"
    )


def test_normalize_https_default_port() -> None:
    assert normalize_url("https://Example.com:443") == "https://example.com/"


def test_preserve_non_default_port() -> None:
    assert normalize_url("https://example.com:8443/login") == ("https://example.com:8443/login")


def test_reject_unsupported_url_scheme() -> None:
    assert normalize_url("ftp://example.com/file.txt") is None


def test_reject_url_credentials() -> None:
    assert normalize_url("https://user:password@example.com") is None


def test_normalize_md5() -> None:
    value = "D41D8CD98F00B204E9800998ECF8427E"

    assert normalize_hash(value) == (
        "md5",
        "d41d8cd98f00b204e9800998ecf8427e",
    )


def test_normalize_sha1() -> None:
    value = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

    assert normalize_hash(value) == (
        "sha1",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    )


def test_normalize_sha256() -> None:
    value = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

    assert normalize_hash(value) == (
        "sha256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_reject_invalid_hash() -> None:
    assert normalize_hash("z" * 64) is None


def test_classify_ipv4() -> None:
    assert classify_entity("192.0.2.42") == NormalizedEntity(
        type="ipv4",
        value="192.0.2.42",
        original="192.0.2.42",
    )


def test_classify_domain() -> None:
    assert classify_entity("Example.COM") == NormalizedEntity(
        type="domain",
        value="example.com",
        original="Example.COM",
    )


def test_classify_url_before_domain_fallback() -> None:
    entity = classify_entity("https://example.com/login")

    assert entity is not None
    assert entity.type == "url"
    assert entity.value == "https://example.com/login"


def test_classify_invalid_value() -> None:
    assert classify_entity("not an observable") is None
