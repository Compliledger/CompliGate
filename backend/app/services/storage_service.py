from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.session import get_engine, persistence_enabled
from app.models.permit import PermitResponse
from app.models.proof import ProofArtifact
from app.repositories.kyc_evidence_repository import create_kyc_evidence_record
from app.repositories.permit_repository import create_permit_record, get_permit_by_bundle_hash
from app.repositories.proof_artifact_repository import create_proof_artifact_record
from app.repositories.reserve_evidence_repository import create_reserve_evidence_record
from app.repositories.sanctions_evidence_repository import create_sanctions_evidence_record

logger = get_logger("main")


def _open_session() -> Session | None:
    engine = get_engine()
    if engine is None:
        return None
    return Session(bind=engine, future=True)


def save_permit(permit: PermitResponse, db: Session | None = None) -> None:
    if not persistence_enabled():
        return
    session = db or _open_session()
    if session is None:
        return
    should_close_session = db is None
    try:
        existing = get_permit_by_bundle_hash(session=session, bundle_hash=permit.bundle_hash)
        if existing is None:
            create_permit_record(session=session, permit=permit)
            try:
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("Failed to persist permit record for bundle_hash=%s", permit.bundle_hash)
                raise
    finally:
        if should_close_session:
            session.close()


def save_proof_artifact(*, bundle_hash: str, artifact: ProofArtifact, artifact_type: str) -> None:
    if not persistence_enabled():
        return
    db = _open_session()
    if db is None:
        return
    try:
        create_proof_artifact_record(
            session=db,
            bundle_hash=bundle_hash,
            artifact=artifact,
            artifact_type=artifact_type,
        )
        db.commit()
    finally:
        db.close()


def _extract_reserve_evidence_fields(
    *,
    evidence_item: Mapping[str, Any],
    asset: str,
    issuer: str,
) -> dict[str, Any]:
    """Normalize a compliance reserve evidence dict into table columns.

    The compliance evidence carries the provider's normalized status and
    its real reference (never a random hash). Both ``reserve_status`` and
    ``liquidity_status`` default to the overall provider status; if the
    provider returned a richer payload that distinguishes the two (under
    ``details.liquidity_status`` / ``details.reserve_status``) those
    explicit values are preserved.
    """

    details = evidence_item.get("details") or {}
    if not isinstance(details, dict):
        details = {}

    overall_status = str(evidence_item.get("status") or "unavailable")
    reserve_status = str(details.get("reserve_status") or overall_status)
    liquidity_status = str(details.get("liquidity_status") or overall_status)

    signature_reference = details.get("signature_reference")
    if signature_reference is not None and not isinstance(signature_reference, str):
        signature_reference = str(signature_reference)

    payload = {
        "check": evidence_item.get("check"),
        "status": overall_status,
        "reason": evidence_item.get("reason"),
        "details": details,
    }

    return {
        "provider_name": str(evidence_item.get("provider_id") or "unknown"),
        "asset": asset or "",
        "issuer": issuer or "",
        "attestation_reference": evidence_item.get("reference"),
        "reserve_status": reserve_status,
        "liquidity_status": liquidity_status,
        "checked_at": int(evidence_item.get("checked_at") or 0),
        "evidence_payload": payload,
        "signature_reference": signature_reference,
    }


def save_reserve_evidence(
    *,
    bundle_hash: str,
    evidence_item: Mapping[str, Any] | None,
    asset: str,
    issuer: str,
    db: Session | None = None,
) -> None:
    """Persist structured reserve / liquidity evidence for a permit decision.

    ``evidence_item`` is the per-check entry produced by
    :func:`evaluate_compliance` for the ``reserve`` provider. The function
    is a no-op when persistence is disabled or when no reserve evidence
    was produced (so callers can invoke it unconditionally).
    """

    if not persistence_enabled():
        return
    if not evidence_item:
        return
    if evidence_item.get("check") not in ("reserve", "liquidity"):
        # Defensive: only persist evidence emitted by the reserve / liquidity check.
        return

    session = db or _open_session()
    if session is None:
        return
    should_close_session = db is None
    try:
        fields = _extract_reserve_evidence_fields(
            evidence_item=evidence_item, asset=asset, issuer=issuer
        )
        create_reserve_evidence_record(session=session, bundle_hash=bundle_hash, **fields)
        try:
            session.commit()
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to persist reserve evidence for bundle_hash=%s", bundle_hash
            )
            raise
    finally:
        if should_close_session:
            session.close()


def _build_normalized_evidence_payload(
    evidence_item: Mapping[str, Any],
) -> dict[str, Any]:
    """Project a compliance evidence dict into safe normalized metadata.

    The returned dict carries only the engine-normalized fields that
    are safe to persist: ``check``, ``status``, ``reason`` and the
    provider-supplied ``details`` dict. Provider credentials, API
    keys, request headers and similar secrets are intentionally never
    propagated -- providers are responsible for keeping them out of
    the evidence ``details`` they emit, and this helper does not pull
    in any other fields. A short ``raw_response_excerpt`` (when the
    provider chose to attach one to ``details``) is preserved as-is so
    auditors retain a bounded, sanitized excerpt of the upstream
    response.
    """

    details = evidence_item.get("details") or {}
    if not isinstance(details, dict):
        details = {}

    return {
        "check": evidence_item.get("check"),
        "status": str(evidence_item.get("status") or "unavailable"),
        "reason": evidence_item.get("reason"),
        "details": details,
    }


def _extract_kyc_evidence_fields(
    *,
    evidence_item: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize a compliance KYC evidence dict into table columns.

    ``provider_name``, ``subject_id``, ``jurisdiction`` and
    ``evidence_reference`` are sourced from the normalized
    ``kyc_result`` block when present (so the persisted row matches
    what the provider actually attested), otherwise they fall back to
    the engine-level evidence fields. The status defaults to the
    overall provider status, never invented.
    """

    details = evidence_item.get("details") or {}
    if not isinstance(details, dict):
        details = {}

    kyc_result = details.get("kyc_result")
    if not isinstance(kyc_result, dict):
        kyc_result = {}

    overall_status = str(evidence_item.get("status") or "unavailable")
    kyc_status = str(kyc_result.get("kyc_status") or overall_status)

    provider_name = (
        kyc_result.get("provider_name")
        or evidence_item.get("provider_id")
        or "unknown"
    )
    evidence_reference = (
        kyc_result.get("evidence_reference")
        if kyc_result.get("evidence_reference") is not None
        else evidence_item.get("reference")
    )

    return {
        "check_type": str(evidence_item.get("check") or "kyc"),
        "provider_name": str(provider_name),
        "subject_id": str(kyc_result.get("subject_id") or ""),
        "jurisdiction": str(kyc_result.get("jurisdiction") or ""),
        "kyc_status": kyc_status,
        "evidence_reference": evidence_reference,
        "checked_at": int(
            kyc_result.get("checked_at")
            or evidence_item.get("checked_at")
            or 0
        ),
        "evidence_payload": _build_normalized_evidence_payload(evidence_item),
    }


def save_kyc_evidence(
    *,
    bundle_hash: str,
    evidence_item: Mapping[str, Any] | None,
    db: Session | None = None,
) -> None:
    """Persist structured KYC evidence for a permit decision.

    ``evidence_item`` is the per-check entry produced by
    :func:`evaluate_compliance` for either the ``kyc`` provider or the
    destination-side ``kyc:destination`` evaluation. The function is a
    no-op when persistence is disabled or when no KYC evidence was
    produced (so callers can invoke it unconditionally).
    """

    if not persistence_enabled():
        return
    if not evidence_item:
        return
    check = evidence_item.get("check")
    if check not in ("kyc", "kyc:destination"):
        # Defensive: only persist evidence emitted by KYC checks.
        return

    session = db or _open_session()
    if session is None:
        return
    should_close_session = db is None
    try:
        fields = _extract_kyc_evidence_fields(evidence_item=evidence_item)
        create_kyc_evidence_record(session=session, bundle_hash=bundle_hash, **fields)
        try:
            session.commit()
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to persist kyc evidence for bundle_hash=%s", bundle_hash
            )
            raise
    finally:
        if should_close_session:
            session.close()


def _extract_sanctions_evidence_fields(
    *,
    evidence_item: Mapping[str, Any],
    subject: str,
    jurisdiction: str,
) -> dict[str, Any]:
    """Normalize a compliance sanctions evidence dict into table columns.

    ``subject`` and ``jurisdiction`` are passed in by the caller (they
    come from the permit request / asset context so they are always
    available, even when the provider did not echo them back). The
    status is the engine-normalized provider status; ``reference`` is
    whatever the provider returned (or ``NULL`` when it did not
    return one).
    """

    return {
        "provider_name": str(evidence_item.get("provider_id") or "unknown"),
        "subject": subject or "",
        "jurisdiction": jurisdiction or "",
        "sanctions_status": str(evidence_item.get("status") or "unavailable"),
        "evidence_reference": evidence_item.get("reference"),
        "checked_at": int(evidence_item.get("checked_at") or 0),
        "evidence_payload": _build_normalized_evidence_payload(evidence_item),
    }


def save_sanctions_evidence(
    *,
    bundle_hash: str,
    evidence_item: Mapping[str, Any] | None,
    subject: str,
    jurisdiction: str,
    db: Session | None = None,
) -> None:
    """Persist structured sanctions screening evidence for a permit decision.

    ``evidence_item`` is the per-check entry produced by
    :func:`evaluate_compliance` for the ``sanctions`` provider. The
    function is a no-op when persistence is disabled or when no
    sanctions evidence was produced (so callers can invoke it
    unconditionally).
    """

    if not persistence_enabled():
        return
    if not evidence_item:
        return
    if evidence_item.get("check") != "sanctions":
        # Defensive: only persist evidence emitted by the sanctions check.
        return

    session = db or _open_session()
    if session is None:
        return
    should_close_session = db is None
    try:
        fields = _extract_sanctions_evidence_fields(
            evidence_item=evidence_item, subject=subject, jurisdiction=jurisdiction
        )
        create_sanctions_evidence_record(session=session, bundle_hash=bundle_hash, **fields)
        try:
            session.commit()
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to persist sanctions evidence for bundle_hash=%s", bundle_hash
            )
            raise
    finally:
        if should_close_session:
            session.close()


def get_permit_context(bundle_hash: str) -> dict | None:
    if not persistence_enabled():
        return None
    db = _open_session()
    if db is None:
        return None
    try:
        permit = get_permit_by_bundle_hash(session=db, bundle_hash=bundle_hash)
        if permit is None:
            return None
        return {
            "bundle_hash": permit.bundle_hash,
            "bundle": permit.bundle_json,
            "proof_artifact": permit.proof_artifact_json,
            "issued_at": permit.signed_at,
        }
    finally:
        db.close()
