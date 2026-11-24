"""Add target_eni and table_outcomes to routes; tighten sync_status constraint.

Removes the terragrunt-era sync states (cloning, planning, applying, pushing)
from the routes table's check constraint and adds the two columns needed
for the AWS-API-backed route provisioning (sc-31774 step 2).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-24

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop the old constraint that includes terragrunt-era states
    op.drop_constraint("ck_routes_sync_status", "routes", type_="check")

    # Re-create with only the states relevant to the AWS-API path
    op.create_check_constraint(
        "ck_routes_sync_status",
        "routes",
        "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
    )

    # Add columns for AWS route tracking
    op.add_column(
        "routes",
        sa.Column("target_eni", sa.Text(), nullable=True),
    )
    op.add_column(
        "routes",
        sa.Column("table_outcomes", JSONB(), nullable=True),
    )

    # Normalize any rows still carrying a removed state to 'failed'
    op.execute(
        "UPDATE routes SET sync_status = 'failed' "
        "WHERE sync_status IN ('cloning', 'planning', 'applying', 'pushing')"
    )


def downgrade() -> None:
    op.drop_column("routes", "table_outcomes")
    op.drop_column("routes", "target_eni")

    op.drop_constraint("ck_routes_sync_status", "routes", type_="check")
    op.create_check_constraint(
        "ck_routes_sync_status",
        "routes",
        "sync_status IN ('synced', 'pending', 'failed', 'pending_delete', 'cloning', 'planning', 'applying', 'pushing')",
    )
