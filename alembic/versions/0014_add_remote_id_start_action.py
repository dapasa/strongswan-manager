"""Add remote_id and start_action to tunnels.

remote_id: optional IKE identity the remote peer presents (falls back to peer_ip when null).
start_action: controls child SA initiation (trap/none/start), default trap.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-22

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tunnels",
        sa.Column("remote_id", sa.Text(), nullable=True),
    )
    op.add_column(
        "tunnels",
        sa.Column("start_action", sa.Text(), nullable=False, server_default="trap"),
    )


def downgrade() -> None:
    op.drop_column("tunnels", "start_action")
    op.drop_column("tunnels", "remote_id")
