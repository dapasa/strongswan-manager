"""Add local_id column to tunnels.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-16

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # local_id is nullable — existing tunnels have no local identity configured.
    # strongSwan defaults to the source IP when the field is absent.
    op.add_column("tunnels", sa.Column("local_id", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("tunnels", "local_id")
