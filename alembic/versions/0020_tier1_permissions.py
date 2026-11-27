"""Add Tier 1 permission system: user_permissions table and shortcut_member_id.

Creates the user_permissions table for per-operator Tier 1 permission grants,
adds shortcut_member_id to the users table, and seeds all Tier 1 permission
keys for every existing operator (opt-in model: admins keep implicit access).

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-26

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TIER1_PERMISSION_KEYS = (
    "tunnels.write",
    "tunnels.connect",
    "tunnels.psk",
    "routes.write",
    "iptables.filter",
    "iptables.snat",
    "capture.headers",
)

_T1_KEYS_SQL = ", ".join(f"'{k}'" for k in TIER1_PERMISSION_KEYS)


def upgrade() -> None:
    # 1. Add shortcut_member_id to users (nullable, unique).
    op.add_column(
        "users",
        sa.Column("shortcut_member_id", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_users_shortcut_member_id",
        "users",
        ["shortcut_member_id"],
        unique=True,
        postgresql_where=sa.text("shortcut_member_id IS NOT NULL"),
    )

    # 2. Create user_permissions table.
    op.create_table(
        "user_permissions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("permission_key", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_user_permissions_user_id",
        ),
        sa.CheckConstraint(
            f"permission_key IN ({_T1_KEYS_SQL})",
            name="ck_user_permissions_key",
        ),
        sa.UniqueConstraint("user_id", "permission_key", name="uq_user_permissions"),
    )
    op.create_index("idx_user_permissions_user_id", "user_permissions", ["user_id"])

    # 3. Seed all Tier 1 permissions for every existing operator.
    #    Admins have permissions implicitly (no DB rows needed).
    #    Viewers never get permissions.
    bind = op.get_bind()
    result = bind.execute(
        sa.text("SELECT id FROM users WHERE role = 'operator' AND is_active = TRUE")
    )
    operator_ids = [row[0] for row in result]

    if operator_ids:
        rows = [
            {"user_id": uid, "permission_key": key}
            for uid in operator_ids
            for key in TIER1_PERMISSION_KEYS
        ]
        bind.execute(
            sa.text(
                "INSERT INTO user_permissions (user_id, permission_key) "
                "VALUES (:user_id, :permission_key) "
                "ON CONFLICT ON CONSTRAINT uq_user_permissions DO NOTHING"
            ),
            rows,
        )


def downgrade() -> None:
    op.drop_table("user_permissions")
    op.drop_index("idx_users_shortcut_member_id", table_name="users")
    op.drop_column("users", "shortcut_member_id")
