from __future__ import annotations

import base64

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from app.core import config


def load_or_create_signing_key() -> SigningKey:
    if config.PRIVATE_KEY_B64:
        try:
            seed = base64.b64decode(config.PRIVATE_KEY_B64)
            if len(seed) != 32:
                raise ValueError("Private key seed must be 32 bytes.")
            return SigningKey(seed, encoder=RawEncoder)
        except Exception as e:
            raise RuntimeError(f"Invalid COMPLIGATE_PRIVATE_KEY_B64: {e}") from e
    return SigningKey.generate()


SIGNING_KEY = load_or_create_signing_key()
VERIFY_KEY = SIGNING_KEY.verify_key


def get_public_key_payload() -> dict:
    pk_raw = VERIFY_KEY.encode(encoder=RawEncoder)
    return {
        "public_key_b64": base64.b64encode(pk_raw).decode("utf-8"),
        "public_key_hex": "0x" + pk_raw.hex(),
    }
