"""Add ike_lifetime column to tunnels.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-16

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add as nullable so existing rows are not rejected.
    op.add_column("tunnels", sa.Column("ike_lifetime", sa.Integer(), nullable=True))

    # 2. Back-fill existing rows with the previously hardcoded default of 86400s.
    op.execute("UPDATE tunnels SET ike_lifetime = 86400")

    # 3. Enforce NOT NULL to match the ORM model.
    op.alter_column("tunnels", "ike_lifetime", nullable=False)


def downgrade() -> None:
    op.drop_column("tunnels", "ike_lifetime")
