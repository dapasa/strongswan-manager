"""Add Tier 2 access requests table and extend audit_logs action constraint.

Creates access_requests for time-limited Shortcut-approved elevated access,
and adds the access_* audit actions (plus restores revoke_sessions dropped
unintentionally in migration 0018).

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-26

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Full audit action set after this migration
_AUDIT_ACTIONS_NEW = (
    "'create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'revoke_sessions',"
    " 'initiate', 'terminate',"
    " 'access_request', 'access_grant', 'access_revoke', 'access_reject', 'access_invalid'"
)

# Audit action set before this migration (as left by 0018)
_AUDIT_ACTIONS_OLD = (
    "'create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'initiate', 'terminate'"
)


def upgrade() -> None:
    # 1. Create access_requests table.
    op.create_table(
        "access_requests",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("permission_key", sa.Text(), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("shortcut_story_id", sa.BigInteger(), nullable=True),
        sa.Column("shortcut_story_url", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="requested"),
        sa.Column("approved_by_member_id", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_access_requests_user_id",
        ),
        sa.CheckConstraint(
            "permission_key IN ('capture.full')",
            name="ck_access_requests_permission_key",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'active', 'rejected', 'invalid', 'revoked', 'expired')",
            name="ck_access_requests_status",
        ),
        sa.CheckConstraint(
            "duration_seconds > 0",
            name="ck_access_requests_duration_pos",
        ),
    )
    op.create_index("idx_access_requests_user_id", "access_requests", ["user_id"])
    op.create_index(
        "idx_access_requests_active",
        "access_requests",
        ["status"],
        postgresql_where=sa.text("status IN ('requested', 'active')"),
    )

    # 2. Extend the audit_logs action constraint with access_* actions.
    #    Also restores 'revoke_sessions' that was dropped in migration 0018.
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        f"action IN ({_AUDIT_ACTIONS_NEW})",
    )


def downgrade() -> None:
    # Restore the pre-0021 audit action constraint (as left by 0018)
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        f"action IN ({_AUDIT_ACTIONS_OLD})",
    )

    op.drop_index("idx_access_requests_active", table_name="access_requests")
    op.drop_index("idx_access_requests_user_id", table_name="access_requests")
    op.drop_table("access_requests")
