"""initial postgres persistence

Revision ID: b3f9f4b2d9c1
Revises: 
Create Date: 2026-04-21 16:31:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b3f9f4b2d9c1"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "permits",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("bundle_id", sa.String(length=128), nullable=False),
        sa.Column("bundle_hash", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=128), nullable=False),
        sa.Column("decision_result", sa.String(length=32), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("bundle_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signed_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("proof_artifact_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_permits_bundle_hash", "permits", ["bundle_hash"], unique=True)
    op.create_index("ix_permits_bundle_id", "permits", ["bundle_id"], unique=False)
    op.create_index("ix_permits_subject", "permits", ["subject"], unique=False)
    op.create_index("ix_permits_action", "permits", ["action"], unique=False)

    op.create_table(
        "proof_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column("module", sa.String(length=64), nullable=False),
        sa.Column("bundle_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_type", sa.String(length=32), nullable=False),
        sa.Column("decision_result", sa.String(length=64), nullable=False),
        sa.Column("rule_version_used", sa.String(length=128), nullable=False),
        sa.Column("evaluation_context_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason_codes_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("timestamp", sa.Integer(), nullable=False),
        sa.Column("anchor_metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_proof_artifacts_entity_id", "proof_artifacts", ["entity_id"], unique=False)
    op.create_index("ix_proof_artifacts_module", "proof_artifacts", ["module"], unique=False)
    op.create_index("ix_proof_artifacts_bundle_hash", "proof_artifacts", ["bundle_hash"], unique=False)
    op.create_index("ix_proof_artifacts_artifact_type", "proof_artifacts", ["artifact_type"], unique=False)
    op.create_index("ix_proof_artifacts_decision_result", "proof_artifacts", ["decision_result"], unique=False)
    op.create_index("ix_proof_artifacts_timestamp", "proof_artifacts", ["timestamp"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_proof_artifacts_timestamp", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_decision_result", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_artifact_type", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_bundle_hash", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_module", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_entity_id", table_name="proof_artifacts")
    op.drop_table("proof_artifacts")

    op.drop_index("ix_permits_action", table_name="permits")
    op.drop_index("ix_permits_subject", table_name="permits")
    op.drop_index("ix_permits_bundle_id", table_name="permits")
    op.drop_index("ix_permits_bundle_hash", table_name="permits")
    op.drop_table("permits")
