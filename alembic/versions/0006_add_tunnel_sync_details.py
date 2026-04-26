"""Add sync_details column and partial to tunnel sync_status constraint.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-26

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tunnels", sa.Column("sync_details", postgresql.JSONB(), nullable=True))

    op.drop_constraint("ck_tunnels_sync_status", "tunnels", type_="check")
    op.create_check_constraint(
        "ck_tunnels_sync_status",
        "tunnels",
        "sync_status IN ('synced', 'pending', 'failed', 'pending_delete', 'partial')",
    )


def downgrade() -> None:
    op.execute("UPDATE tunnels SET sync_status = 'failed' WHERE sync_status = 'partial'")

    op.drop_constraint("ck_tunnels_sync_status", "tunnels", type_="check")
    op.create_check_constraint(
        "ck_tunnels_sync_status",
        "tunnels",
        "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
    )

    op.drop_column("tunnels", "sync_details")
