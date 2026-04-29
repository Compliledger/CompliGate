"""Tests for ``app.services.hashing``."""

from __future__ import annotations

import hashlib
import json

from app.services.hashing import canonicalize_json, sha256_hash


def test_same_data_different_key_order_produces_same_hash():
    a = {"b": 1, "a": 2, "c": {"y": 10, "x": 20}}
    b = {"a": 2, "c": {"x": 20, "y": 10}, "b": 1}

    assert sha256_hash(a) == sha256_hash(b)
    assert canonicalize_json(a) == canonicalize_json(b)


def test_canonicalize_json_sorts_keys_and_uses_stable_separators():
    data = {"b": 1, "a": 2}
    assert canonicalize_json(data) == b'{"a":2,"b":1}'


def test_canonicalize_json_removes_null_values_recursively():
    data = {
        "a": 1,
        "b": None,
        "c": {"d": None, "e": 2},
        "f": [{"g": None, "h": 3}, {"i": None}],
    }
    expected = {"a": 1, "c": {"e": 2}, "f": [{"h": 3}, {}]}
    assert canonicalize_json(data) == json.dumps(
        expected, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def test_canonicalize_json_returns_utf8_bytes():
    data = {"name": "café", "emoji": "✓"}
    out = canonicalize_json(data)

    assert isinstance(out, bytes)
    # Round-trip through UTF-8 to confirm encoding.
    assert json.loads(out.decode("utf-8")) == data


def test_sha256_hash_matches_manual_computation():
    data = {"a": 1, "b": 2}
    canonical = canonicalize_json(data)
    assert sha256_hash(data) == hashlib.sha256(canonical).hexdigest()


def test_sha256_hash_ignores_explicit_null_fields():
    with_nulls = {"a": 1, "b": None}
    without_nulls = {"a": 1}
    assert sha256_hash(with_nulls) == sha256_hash(without_nulls)
