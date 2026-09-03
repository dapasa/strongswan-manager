"""Add psk_secret_name column to tunnels.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-03

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add as nullable so existing rows (if any) are not rejected.
    op.add_column("tunnels", sa.Column("psk_secret_name", sa.Text(), nullable=True))

    # 2. Back-fill preexisting rows using the same formula as tunnel_service.py:
    #    psk_secret_name = f"secrets/{name}.secrets"
    op.execute("UPDATE tunnels SET psk_secret_name = 'secrets/' || name || '.secrets'")

    # 3. Now that every row has a value, enforce NOT NULL to match the ORM model.
    op.alter_column("tunnels", "psk_secret_name", nullable=False)


def downgrade() -> None:
    op.drop_column("tunnels", "psk_secret_name")
