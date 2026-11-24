"""Add initiate and terminate to audit_logs action constraint.

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-24

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ('create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'initiate', 'terminate')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ('create', 'update', 'delete', 'retry', 'login', 'rotate_psk')",
    )
