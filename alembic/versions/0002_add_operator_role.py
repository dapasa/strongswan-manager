"""Add operator role to users check constraint.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-13

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_users_role", "users")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin', 'operator', 'viewer')",
    )


def downgrade() -> None:
    # Convert any operator users to viewer before restricting constraint
    op.execute("UPDATE users SET role = 'viewer' WHERE role = 'operator'")
    op.drop_constraint("ck_users_role", "users")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin', 'viewer')",
    )
