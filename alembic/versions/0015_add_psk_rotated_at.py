"""Add psk_rotated_at to tunnels; add rotate_psk to audit_logs action constraint.

psk_rotated_at: timestamptz nullable — set on tunnel create, PSK update, and rotation.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-16

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tunnels",
        sa.Column("psk_rotated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ('create', 'update', 'delete', 'retry', 'login', 'rotate_psk')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ('create', 'update', 'delete', 'retry', 'login')",
    )
    op.drop_column("tunnels", "psk_rotated_at")
