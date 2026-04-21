from __future__ import annotations

from pydantic import BaseModel

try:
    from proofbundle import ProofArtifact, build_proof_artifact  # type: ignore[import]
except ImportError:
    class ProofArtifact(BaseModel):  # type: ignore[no-redef]
        module: str
        entity_id: str
        rule_version_used: str
        decision_result: str
        evaluation_context: dict
        reason_codes: list[str]
        timestamp: int
        bundle_hash: str
        anchor_metadata: dict

    def build_proof_artifact(  # type: ignore[misc]
        *,
        module: str,
        entity_id: str,
        rule_version_used: str,
        decision_result: str,
        evaluation_context: dict,
        reason_codes: list[str],
        timestamp: int,
        bundle_hash: str,
        anchor_metadata: dict,
    ) -> "ProofArtifact":
        return ProofArtifact(
            module=module,
            entity_id=entity_id,
            rule_version_used=rule_version_used,
            decision_result=decision_result,
            evaluation_context=evaluation_context,
            reason_codes=reason_codes,
            timestamp=timestamp,
            bundle_hash=bundle_hash,
            anchor_metadata=anchor_metadata,
        )
