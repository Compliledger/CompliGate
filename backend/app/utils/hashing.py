from __future__ import annotations

import hashlib

from app.utils.canonical_json import canonical_json


def proof_hash(bundle: dict) -> str:
    canonical = canonical_json(bundle).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
