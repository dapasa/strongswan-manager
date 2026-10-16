"""Add ipsec_engine column to servers.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-16

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add as nullable so existing rows are not rejected.
    op.add_column("servers", sa.Column("ipsec_engine", sa.Text(), nullable=True))

    # 2. Back-fill existing rows with 'stroke' (prod servers use the legacy daemon).
    op.execute("UPDATE servers SET ipsec_engine = 'stroke'")

    # 3. Enforce NOT NULL to match the ORM model.
    op.alter_column("servers", "ipsec_engine", nullable=False)

    # 4. Constrain values.
    op.create_check_constraint(
        "ck_servers_ipsec_engine",
        "servers",
        "ipsec_engine IN ('swanctl', 'stroke')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_servers_ipsec_engine", "servers", type_="check")
    op.drop_column("servers", "ipsec_engine")
