"""Add truncated_by_size column to packet_captures.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "packet_captures",
        sa.Column(
            "truncated_by_size",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("packet_captures", "truncated_by_size")
