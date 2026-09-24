"""Normalisation and classification of security observables."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import tldextract

EntityType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
]

_HASH_LENGTHS: dict[int, EntityType] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Use tldextract's packaged Public Suffix List snapshot.
# This avoids a network request during normalisation.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True, slots=True)
class NormalizedEntity:
    """A validated and normalised security observable."""

    type: EntityType
    value: str
    original: str


def normalize_ip(value: str) -> tuple[EntityType, str] | None:
    """Return a canonical IPv4 or IPv6 address."""

    candidate = value.strip()

    if not candidate:
        return None

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv4Address):
        return "ipv4", str(address)

    return "ipv6", address.compressed


def normalize_domain(value: str) -> str | None:
    """Validate and normalise a fully qualified domain name."""

    candidate = value.strip().rstrip(".").lower()

    if not candidate:
        return None

    # Domains must not contain URL/path components.
    if any(character in candidate for character in ("/", "\\", ":", "@")):
        return None

    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(ascii_domain) > 253:
        return None

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        return None

    for label in labels:
        if not label or len(label) > 63:
            return None

        if label.startswith("-") or label.endswith("-"):
            return None

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None

    extracted = _TLD_EXTRACTOR(ascii_domain)

    if not extracted.domain or not extracted.suffix:
        return None

    return ascii_domain


def normalize_url(value: str) -> str | None:
    """Normalise an HTTP(S) URL while preserving meaningful path/query data."""

    candidate = value.strip()

    if not candidate:
        return None

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        return None

    if not parsed.hostname:
        return None

    host_ip = normalize_ip(parsed.hostname)

    if host_ip is not None:
        _, normalized_hostname = host_ip

        if ":" in normalized_hostname:
            normalized_hostname = f"[{normalized_hostname}]"
    else:
        normalized_domain = normalize_domain(parsed.hostname)

        if normalized_domain is None:
            return None

        normalized_hostname = normalized_domain

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = normalized_hostname
    else:
        netloc = f"{normalized_hostname}:{port}"

    if parsed.username is not None or parsed.password is not None:
        return None

    path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def normalize_hash(value: str) -> tuple[EntityType, str] | None:
    """Validate MD5, SHA-1 or SHA-256 hexadecimal digests."""

    candidate = value.strip().lower()

    hash_type = _HASH_LENGTHS.get(len(candidate))

    if hash_type is None:
        return None

    if _HEX_RE.fullmatch(candidate) is None:
        return None

    # Verify that Python's hashing implementation recognises the digest type.
    algorithm_names = {
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
    }

    if algorithm_names[hash_type] not in hashlib.algorithms_available:
        return None

    return hash_type, candidate


def classify_entity(value: str) -> NormalizedEntity | None:
    """Classify and normalise a supported security observable."""

    original = value

    ip_result = normalize_ip(value)

    if ip_result is not None:
        entity_type, normalized_value = ip_result
        return NormalizedEntity(
            type=entity_type,
            value=normalized_value,
            original=original,
        )

    hash_result = normalize_hash(value)

    if hash_result is not None:
        entity_type, normalized_value = hash_result
        return NormalizedEntity(
            type=entity_type,
            value=normalized_value,
            original=original,
        )

    url_result = normalize_url(value)

    if url_result is not None:
        return NormalizedEntity(
            type="url",
            value=url_result,
            original=original,
        )

    domain_result = normalize_domain(value)

    if domain_result is not None:
        return NormalizedEntity(
            type="domain",
            value=domain_result,
            original=original,
        )

    return None
