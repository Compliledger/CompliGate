"""add kyc_evidence and sanctions_evidence tables

Revision ID: d5b2e9f3a7c4
Revises: c4a7d2e1f0a2
Create Date: 2026-04-26 16:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "d5b2e9f3a7c4"
down_revision: Union[str, None] = "c4a7d2e1f0a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "kyc_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("bundle_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "check_type",
            sa.String(length=32),
            nullable=False,
            server_default="kyc",
        ),
        sa.Column("provider_name", sa.String(length=128), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("jurisdiction", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("kyc_status", sa.String(length=32), nullable=False),
        sa.Column("evidence_reference", sa.String(length=512), nullable=True),
        sa.Column("checked_at", sa.Integer(), nullable=False),
        sa.Column(
            "evidence_payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_kyc_evidence_bundle_hash", "kyc_evidence", ["bundle_hash"], unique=False)
    op.create_index("ix_kyc_evidence_check_type", "kyc_evidence", ["check_type"], unique=False)
    op.create_index("ix_kyc_evidence_provider_name", "kyc_evidence", ["provider_name"], unique=False)
    op.create_index("ix_kyc_evidence_subject_id", "kyc_evidence", ["subject_id"], unique=False)
    op.create_index("ix_kyc_evidence_jurisdiction", "kyc_evidence", ["jurisdiction"], unique=False)
    op.create_index("ix_kyc_evidence_kyc_status", "kyc_evidence", ["kyc_status"], unique=False)
    op.create_index("ix_kyc_evidence_checked_at", "kyc_evidence", ["checked_at"], unique=False)

    op.create_table(
        "sanctions_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("bundle_hash", sa.String(length=64), nullable=False),
        sa.Column("provider_name", sa.String(length=128), nullable=False),
        sa.Column("subject", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("jurisdiction", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("sanctions_status", sa.String(length=32), nullable=False),
        sa.Column("evidence_reference", sa.String(length=512), nullable=True),
        sa.Column("checked_at", sa.Integer(), nullable=False),
        sa.Column(
            "evidence_payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sanctions_evidence_bundle_hash", "sanctions_evidence", ["bundle_hash"], unique=False
    )
    op.create_index(
        "ix_sanctions_evidence_provider_name",
        "sanctions_evidence",
        ["provider_name"],
        unique=False,
    )
    op.create_index(
        "ix_sanctions_evidence_subject", "sanctions_evidence", ["subject"], unique=False
    )
    op.create_index(
        "ix_sanctions_evidence_jurisdiction",
        "sanctions_evidence",
        ["jurisdiction"],
        unique=False,
    )
    op.create_index(
        "ix_sanctions_evidence_sanctions_status",
        "sanctions_evidence",
        ["sanctions_status"],
        unique=False,
    )
    op.create_index(
        "ix_sanctions_evidence_checked_at",
        "sanctions_evidence",
        ["checked_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_sanctions_evidence_checked_at", table_name="sanctions_evidence")
    op.drop_index("ix_sanctions_evidence_sanctions_status", table_name="sanctions_evidence")
    op.drop_index("ix_sanctions_evidence_jurisdiction", table_name="sanctions_evidence")
    op.drop_index("ix_sanctions_evidence_subject", table_name="sanctions_evidence")
    op.drop_index("ix_sanctions_evidence_provider_name", table_name="sanctions_evidence")
    op.drop_index("ix_sanctions_evidence_bundle_hash", table_name="sanctions_evidence")
    op.drop_table("sanctions_evidence")

    op.drop_index("ix_kyc_evidence_checked_at", table_name="kyc_evidence")
    op.drop_index("ix_kyc_evidence_kyc_status", table_name="kyc_evidence")
    op.drop_index("ix_kyc_evidence_jurisdiction", table_name="kyc_evidence")
    op.drop_index("ix_kyc_evidence_subject_id", table_name="kyc_evidence")
    op.drop_index("ix_kyc_evidence_provider_name", table_name="kyc_evidence")
    op.drop_index("ix_kyc_evidence_check_type", table_name="kyc_evidence")
    op.drop_index("ix_kyc_evidence_bundle_hash", table_name="kyc_evidence")
    op.drop_table("kyc_evidence")
