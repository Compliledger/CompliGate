"""add reserve_evidence table

Revision ID: c4a7d2e1f0a2
Revises: b3f9f4b2d9c1
Create Date: 2026-04-23 13:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c4a7d2e1f0a2"
down_revision: Union[str, None] = "b3f9f4b2d9c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "reserve_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("bundle_hash", sa.String(length=64), nullable=False),
        sa.Column("provider_name", sa.String(length=128), nullable=False),
        sa.Column("asset", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("attestation_reference", sa.String(length=512), nullable=True),
        sa.Column("reserve_status", sa.String(length=32), nullable=False),
        sa.Column("liquidity_status", sa.String(length=32), nullable=False),
        sa.Column("checked_at", sa.Integer(), nullable=False),
        sa.Column(
            "evidence_payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("signature_reference", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_reserve_evidence_bundle_hash", "reserve_evidence", ["bundle_hash"], unique=False
    )
    op.create_index(
        "ix_reserve_evidence_provider_name", "reserve_evidence", ["provider_name"], unique=False
    )
    op.create_index(
        "ix_reserve_evidence_asset", "reserve_evidence", ["asset"], unique=False
    )
    op.create_index(
        "ix_reserve_evidence_issuer", "reserve_evidence", ["issuer"], unique=False
    )
    op.create_index(
        "ix_reserve_evidence_reserve_status",
        "reserve_evidence",
        ["reserve_status"],
        unique=False,
    )
    op.create_index(
        "ix_reserve_evidence_liquidity_status",
        "reserve_evidence",
        ["liquidity_status"],
        unique=False,
    )
    op.create_index(
        "ix_reserve_evidence_checked_at", "reserve_evidence", ["checked_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_reserve_evidence_checked_at", table_name="reserve_evidence")
    op.drop_index("ix_reserve_evidence_liquidity_status", table_name="reserve_evidence")
    op.drop_index("ix_reserve_evidence_reserve_status", table_name="reserve_evidence")
    op.drop_index("ix_reserve_evidence_issuer", table_name="reserve_evidence")
    op.drop_index("ix_reserve_evidence_asset", table_name="reserve_evidence")
    op.drop_index("ix_reserve_evidence_provider_name", table_name="reserve_evidence")
    op.drop_index("ix_reserve_evidence_bundle_hash", table_name="reserve_evidence")
    op.drop_table("reserve_evidence")
