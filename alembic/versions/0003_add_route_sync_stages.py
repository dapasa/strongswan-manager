"""Add granular sync_status stages for routes.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-20

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_routes_sync_status", "routes")
    op.create_check_constraint(
        "ck_routes_sync_status",
        "routes",
        "sync_status IN ('synced', 'pending', 'failed', 'pending_delete', 'cloning', 'planning', 'applying', 'pushing')",
    )


def downgrade() -> None:
    # Reset any in-progress routes back to pending before restricting constraint
    op.execute(
        "UPDATE routes SET sync_status = 'pending' "
        "WHERE sync_status IN ('cloning', 'planning', 'applying', 'pushing')"
    )
    op.drop_constraint("ck_routes_sync_status", "routes")
    op.create_check_constraint(
        "ck_routes_sync_status",
        "routes",
        "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
    )
