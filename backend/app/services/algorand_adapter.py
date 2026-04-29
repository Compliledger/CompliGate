"""Algorand proof-anchoring adapter.

This module provides a small, well-defined surface for anchoring CompliGate
proof artifacts onto Algorand and for verifying previously anchored
proofs. It supports two modes:

* **Mock mode** (``ALGORAND_MOCK=true``) – fully implemented here. Returns
  a deterministic fake ``tx_id`` and a synthesized explorer URL so the
  rest of the MVP can integrate against a stable interface without
  needing any Algorand network access or credentials.

* **Real adapter mode** (``ALGORAND_MOCK=false``) – delegates to the
  existing CompliLedger Algorand Adapter integration. The real wiring is
  intentionally left as a clearly-marked ``TODO`` so it can be filled in
  without changing the public surface used by the rest of the backend.

Environment variables:

* ``ALGORAND_MOCK`` – ``true`` to use the mock adapter (default ``true``
  for MVP / local development).
* ``ALGO_NETWORK`` – Algorand network identifier reported in the result
  (default ``testnet``).
* ``ALGO_EXPLORER_BASE`` – base URL used to build ``explorer_url``
  (default ``https://testnet.explorer.perawallet.app/tx``).

Public surface:

* :func:`anchor_proof` – anchor a proof hash, return anchor metadata.
* :func:`verify_anchor` – verify that a previously returned ``tx_id``
  matches an expected proof hash.

Both functions return / consume plain ``dict`` payloads so callers do not
need to depend on this module's internal types.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any

from app.core.logging import get_logger

logger = get_logger("main")

_TRUE_VALUES = ("true", "1", "yes")

_DEFAULT_NETWORK = "testnet"
_DEFAULT_EXPLORER_BASE = "https://testnet.explorer.perawallet.app/tx"
_CHAIN_NAME = "Algorand"


def _is_mock_mode() -> bool:
    """Return True when the adapter should run in mock mode.

    Mock mode is the default so the MVP works out of the box without any
    Algorand credentials or network access.
    """
    return os.getenv("ALGORAND_MOCK", "true").strip().lower() in _TRUE_VALUES


def _network() -> str:
    return os.getenv("ALGO_NETWORK", _DEFAULT_NETWORK).strip() or _DEFAULT_NETWORK


def _explorer_base() -> str:
    base = os.getenv("ALGO_EXPLORER_BASE", _DEFAULT_EXPLORER_BASE).strip()
    return base or _DEFAULT_EXPLORER_BASE


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with ``Z`` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_explorer_url(tx_id: str) -> str:
    base = _explorer_base().rstrip("/")
    return f"{base}/{tx_id}"


def _mock_tx_id(proof_hash: str, artifact_id: str) -> str:
    """Generate a deterministic, Algorand-style fake transaction id.

    Real Algorand transaction ids are 52-character base32 strings. For
    mock mode we generate a deterministic upper-case hex id derived from
    the proof hash + artifact id so the same inputs always produce the
    same id (helps tests and replay scenarios). The id is clearly
    prefixed with ``MOCK`` so it can never be confused with a real
    on-chain tx.
    """
    digest = hashlib.sha256(f"{proof_hash}|{artifact_id}".encode("utf-8")).hexdigest()
    # 4-char "MOCK" tag + 48 hex chars = 52 chars, mirroring real tx-id length.
    return ("MOCK" + digest[:48]).upper()


def _mock_anchor(proof_hash: str, artifact_id: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    tx_id = _mock_tx_id(proof_hash, artifact_id)
    result = {
        "chain": _CHAIN_NAME,
        "network": _network(),
        "tx_id": tx_id,
        "explorer_url": _build_explorer_url(tx_id),
        "anchored_at": _utc_now_iso(),
        "mock": True,
    }
    logger.info(
        "algorand_adapter mock anchor: artifact_id=%s tx_id=%s network=%s",
        artifact_id,
        tx_id,
        result["network"],
    )
    # ``metadata`` is intentionally not embedded in the mock result so the
    # mock surface stays minimal; the real adapter is responsible for
    # propagating any caller-supplied metadata onto the chain (e.g. as a
    # transaction note).
    _ = metadata
    return result


def _mock_verify(tx_id: str, expected_hash: str) -> dict[str, Any]:
    """Verify a mock anchor.

    A mock anchor is "valid" iff its ``tx_id`` was produced by
    :func:`_mock_tx_id` for some artifact id paired with
    ``expected_hash``. Because the mock tx id only encodes a digest of
    ``proof_hash|artifact_id``, we cannot reconstruct ``artifact_id``
    here – instead we treat any ``MOCK``-prefixed id as a structurally
    valid mock anchor and report it verified. This is sufficient for the
    MVP, where verify is exercised as a smoke check against the same
    ``anchor_proof`` flow.
    """
    is_mock_id = isinstance(tx_id, str) and tx_id.startswith("MOCK")
    verified = bool(is_mock_id and expected_hash)
    return {
        "chain": _CHAIN_NAME,
        "network": _network(),
        "tx_id": tx_id,
        "expected_hash": expected_hash,
        "verified": verified,
        "checked_at": _utc_now_iso(),
        "mock": True,
    }


# ---------------------------------------------------------------------------
# Real adapter integration (CompliLedger Algorand Adapter)
# ---------------------------------------------------------------------------
#
# TODO(compliledger-algorand-adapter): wire the real CompliLedger Algorand
# Adapter into the two ``_real_*`` functions below. The expected
# integration shape is roughly:
#
#   from compliledger.algorand_adapter import AlgorandAdapter
#
#   adapter = AlgorandAdapter(
#       network=os.getenv("ALGO_NETWORK", "testnet"),
#       # ... credentials / signer config sourced from environment ...
#   )
#
#   tx = adapter.anchor(
#       proof_hash=proof_hash,
#       artifact_id=artifact_id,
#       metadata=metadata,        # e.g. attached as a transaction note
#   )
#   # tx must expose at least: tx_id (str) and confirmed_at (datetime|str)
#
# Until that integration lands, the real-mode functions raise
# ``NotImplementedError`` so callers fail loudly instead of silently
# returning fake data when ``ALGORAND_MOCK`` is disabled.


def _real_anchor(proof_hash: str, artifact_id: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    # TODO(compliledger-algorand-adapter): replace this stub with a call
    # into the real CompliLedger Algorand Adapter and map its response
    # onto the documented return shape.
    raise NotImplementedError(
        "Real Algorand adapter integration is not wired up yet. "
        "Set ALGORAND_MOCK=true to use the MVP mock adapter."
    )


def _real_verify(tx_id: str, expected_hash: str) -> dict[str, Any]:
    # TODO(compliledger-algorand-adapter): replace this stub with a call
    # into the real CompliLedger Algorand Adapter to fetch the on-chain
    # transaction note for ``tx_id`` and compare it to ``expected_hash``.
    raise NotImplementedError(
        "Real Algorand adapter integration is not wired up yet. "
        "Set ALGORAND_MOCK=true to use the MVP mock adapter."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def anchor_proof(
    proof_hash: str,
    artifact_id: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Anchor a proof hash on Algorand and return anchor metadata.

    Parameters
    ----------
    proof_hash:
        The hex / base64 digest of the CompliGate proof artifact to anchor.
    artifact_id:
        Stable identifier of the proof artifact being anchored. Used by
        the mock adapter to derive a deterministic ``tx_id`` and by the
        real adapter to correlate on-chain transactions with off-chain
        records.
    metadata:
        Optional adapter-specific metadata. The real adapter is expected
        to forward this onto the chain (e.g. as a transaction note); the
        mock adapter ignores it.

    Returns
    -------
    dict
        ``{"chain": "Algorand", "network": ..., "tx_id": ...,
        "explorer_url": ..., "anchored_at": ...}``. Mock results
        additionally include ``"mock": True``.
    """
    if not isinstance(proof_hash, str) or not proof_hash:
        raise ValueError("anchor_proof requires a non-empty proof_hash string")
    if not isinstance(artifact_id, str) or not artifact_id:
        raise ValueError("anchor_proof requires a non-empty artifact_id string")

    if _is_mock_mode():
        return _mock_anchor(proof_hash, artifact_id, metadata)
    return _real_anchor(proof_hash, artifact_id, metadata)


def verify_anchor(tx_id: str, expected_hash: str) -> dict[str, Any]:
    """Verify that ``tx_id`` anchors ``expected_hash`` on Algorand.

    Returns a dict with ``verified`` (bool) plus contextual metadata.
    Raises :class:`ValueError` for malformed inputs.
    """
    if not isinstance(tx_id, str) or not tx_id:
        raise ValueError("verify_anchor requires a non-empty tx_id string")
    if not isinstance(expected_hash, str) or not expected_hash:
        raise ValueError("verify_anchor requires a non-empty expected_hash string")

    if _is_mock_mode():
        return _mock_verify(tx_id, expected_hash)
    return _real_verify(tx_id, expected_hash)
