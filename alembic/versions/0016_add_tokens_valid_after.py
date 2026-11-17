"""Add tokens_valid_after to users; add revoke_sessions to audit_logs action constraint.

tokens_valid_after: timestamptz nullable — when set, tokens issued before this timestamp
are rejected, allowing "sign out everywhere" without deactivating the account.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-17

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("tokens_valid_after", sa.DateTime(timezone=True), nullable=True),
    )
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ('create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'revoke_sessions')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ('create', 'update', 'delete', 'retry', 'login', 'rotate_psk')",
    )
    op.drop_column("users", "tokens_valid_after")
