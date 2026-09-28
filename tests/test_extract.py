"""Tests for SOC entity extraction."""

from threat_intel_enrichment.extract import (
    ExtractedEntity,
    extract_entities,
    get_nested_value,
)
from threat_intel_enrichment.normalize import NormalizedEntity


def test_get_nested_value() -> None:
    event = {
        "source": {
            "ip": "192.0.2.10",
        }
    }

    assert get_nested_value(event, "source.ip") == "192.0.2.10"


def test_get_nested_value_missing_field() -> None:
    event = {
        "source": {
            "ip": "192.0.2.10",
        }
    }

    assert get_nested_value(event, "destination.ip") is None


def test_extract_source_and_destination_ips() -> None:
    event = {
        "source": {
            "ip": "192.0.2.10",
        },
        "destination": {
            "ip": "198.51.100.20",
        },
    }

    result = extract_entities(event)

    assert len(result) == 2

    assert result[0] == ExtractedEntity(
        entity=NormalizedEntity(
            type="ipv4",
            value="192.0.2.10",
            original="192.0.2.10",
        ),
        field="source.ip",
    )


def test_extract_domain() -> None:
    event = {
        "dns": {
            "question": {
                "name": "Example.COM.",
            }
        }
    }

    result = extract_entities(event)

    assert len(result) == 1
    assert result[0].entity.type == "domain"
    assert result[0].entity.value == "example.com"
    assert result[0].field == "dns.question.name"


def test_extract_url() -> None:
    event = {
        "url": {
            "full": "https://Example.com/login",
        }
    }

    result = extract_entities(event)

    assert len(result) == 1
    assert result[0].entity.type == "url"
    assert result[0].entity.value == "https://example.com/login"


def test_extract_hash() -> None:
    event = {
        "file": {
            "hash": {"sha256": ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")}
        }
    }

    result = extract_entities(event)

    assert len(result) == 1
    assert result[0].entity.type == "sha256"


def test_extract_list_of_ips() -> None:
    event = {
        "host": {
            "ip": [
                "192.0.2.1",
                "2001:db8::1",
            ]
        }
    }

    result = extract_entities(event)

    assert len(result) == 2

    assert {item.entity.type for item in result} == {
        "ipv4",
        "ipv6",
    }


def test_ignore_invalid_observable() -> None:
    event = {
        "source": {
            "ip": "definitely-not-an-ip",
        }
    }

    assert extract_entities(event) == []


def test_custom_fields() -> None:
    event = {
        "indicator": {
            "value": "example.com",
        }
    }

    result = extract_entities(
        event,
        fields=("indicator.value",),
    )

    assert len(result) == 1
    assert result[0].entity.type == "domain"
