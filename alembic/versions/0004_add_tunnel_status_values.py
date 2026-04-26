"""Add up/down/unknown to tunnel status CHECK constraint.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-20

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_tunnels_status", "tunnels")
    op.create_check_constraint(
        "ck_tunnels_status",
        "tunnels",
        "status IN ('active', 'inactive', 'up', 'down', 'unknown')",
    )


def downgrade() -> None:
    # Reset runtime statuses back to 'active' before restricting constraint
    op.execute(
        "UPDATE tunnels SET status = 'active' "
        "WHERE status IN ('up', 'down', 'unknown')"
    )
    op.drop_constraint("ck_tunnels_status", "tunnels")
    op.create_check_constraint(
        "ck_tunnels_status",
        "tunnels",
        "status IN ('active', 'inactive')",
    )
