"""Extraction of security observables from structured SOC events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from threat_intel_enrichment.normalize import NormalizedEntity, classify_entity


@dataclass(frozen=True, slots=True)
class ExtractedEntity:
    """A normalised entity together with its source field."""

    entity: NormalizedEntity
    field: str


DEFAULT_ENTITY_FIELDS: tuple[str, ...] = (
    "source.ip",
    "destination.ip",
    "client.ip",
    "server.ip",
    "host.ip",
    "dns.question.name",
    "url.full",
    "url.domain",
    "destination.domain",
    "source.domain",
    "file.hash.md5",
    "file.hash.sha1",
    "file.hash.sha256",
)


def get_nested_value(
    event: Mapping[str, Any],
    dotted_path: str,
) -> Any | None:
    """Retrieve a value from nested dictionaries using a dotted field path."""

    current: Any = event

    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return None

        if part not in current:
            return None

        current = current[part]

    return current


def _iter_candidate_values(value: Any) -> Iterable[str]:
    """Yield candidate strings from scalar or list-like event fields."""

    if isinstance(value, str):
        stripped = value.strip()

        if stripped:
            yield stripped

    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                stripped = item.strip()

                if stripped:
                    yield stripped


def extract_entities(
    event: Mapping[str, Any],
    *,
    fields: Iterable[str] = DEFAULT_ENTITY_FIELDS,
) -> list[ExtractedEntity]:
    """Extract supported observables from a structured SOC event."""

    extracted: list[ExtractedEntity] = []
    seen: set[tuple[str, str, str]] = set()

    for field in fields:
        value = get_nested_value(event, field)

        if value is None:
            continue

        for candidate in _iter_candidate_values(value):
            entity = classify_entity(candidate)

            if entity is None:
                continue

            dedupe_key = (
                field,
                entity.type,
                entity.value,
            )

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            extracted.append(
                ExtractedEntity(
                    entity=entity,
                    field=field,
                )
            )

    return extracted
