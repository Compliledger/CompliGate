"""Canonical JSON serialization and SHA-256 hashing helpers.

This module provides a deterministic JSON canonicalization routine and a
SHA-256 helper built on top of it. The canonical form is used wherever a
hash needs to be reproducible from structured data (e.g. proofs, evidence
bundles), so the rules are intentionally strict:

* Object keys are sorted lexicographically (recursively).
* ``None`` values are removed (recursively, including from nested objects
  and from objects nested inside arrays).
* Stable, whitespace-free separators are used (``","`` and ``":"``).
* The result is encoded as UTF-8 bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _strip_nulls(value: Any) -> Any:
    """Recursively remove keys whose values are ``None``.

    Lists are walked so that dictionaries nested inside arrays are also
    cleaned. Non-container values are returned unchanged.
    """

    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value]
    return value


def canonicalize_json(data: Any) -> bytes:
    """Return a canonical UTF-8 encoded JSON representation of ``data``.

    The output is deterministic for any two semantically equivalent
    inputs: keys are sorted, ``None`` values are dropped, and stable
    separators are used so the byte sequence depends only on the data.
    """

    cleaned = _strip_nulls(data)
    serialized = json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return serialized.encode("utf-8")


def sha256_hash(data: Any) -> str:
    """Return the SHA-256 hex digest of the canonicalized JSON for ``data``."""

    return hashlib.sha256(canonicalize_json(data)).hexdigest()
