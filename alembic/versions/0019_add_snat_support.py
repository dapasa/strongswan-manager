"""Add SNAT support to iptables_rules (nat table / POSTROUTING chain).

Adds rule_table and to_source columns, widens chain/action constraints,
adds a consistency constraint, and updates the unique partial index.

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-25

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add rule_table column (default 'filter', not null).
    #    All existing rows get 'filter' via the server_default.
    op.add_column(
        "iptables_rules",
        sa.Column("rule_table", sa.Text(), nullable=False, server_default="filter"),
    )

    # 2. Add to_source column (INET, nullable — required only for nat/SNAT rules).
    op.add_column(
        "iptables_rules",
        sa.Column("to_source", postgresql.INET(), nullable=True),
    )

    # 3. Add rule_table value constraint.
    op.create_check_constraint(
        "ck_iptables_rule_table",
        "iptables_rules",
        "rule_table IN ('filter', 'nat')",
    )

    # 4. Widen chain constraint to include POSTROUTING.
    op.drop_constraint("ck_iptables_chain", "iptables_rules", type_="check")
    op.create_check_constraint(
        "ck_iptables_chain",
        "iptables_rules",
        "chain IN ('INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING')",
    )

    # 5. Widen action constraint to include SNAT.
    op.drop_constraint("ck_iptables_action", "iptables_rules", type_="check")
    op.create_check_constraint(
        "ck_iptables_action",
        "iptables_rules",
        "action IN ('ACCEPT', 'DROP', 'REJECT', 'SNAT')",
    )

    # 6. Add consistency constraint: filter rules keep to_source=NULL;
    #    nat/SNAT rules require to_source IS NOT NULL.
    #    All existing rows satisfy the filter branch automatically.
    op.create_check_constraint(
        "ck_iptables_nat_consistency",
        "iptables_rules",
        "(rule_table = 'filter' AND chain IN ('INPUT', 'FORWARD', 'OUTPUT')"
        " AND action IN ('ACCEPT', 'DROP', 'REJECT') AND to_source IS NULL)"
        " OR (rule_table = 'nat' AND chain = 'POSTROUTING'"
        " AND action = 'SNAT' AND to_source IS NOT NULL)",
    )

    # 7. Drop the old unique partial index (didn't cover rule_table / to_source).
    op.drop_index("idx_iptables_unique_rule", table_name="iptables_rules")

    # 8. Recreate it including the new columns so nat and filter rules are
    #    distinguished even when other fields are identical.
    op.create_index(
        "idx_iptables_unique_rule",
        "iptables_rules",
        ["tunnel_id", "rule_table", "chain", "protocol", "source_cidr", "dest_cidr", "dport", "action", "to_source"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    # Reverse in the opposite order.

    # 1. Remove the new unique index.
    op.drop_index("idx_iptables_unique_rule", table_name="iptables_rules")

    # 2. Remove the consistency constraint.
    op.drop_constraint("ck_iptables_nat_consistency", "iptables_rules", type_="check")

    # 3. Restore narrow action constraint (will fail if SNAT rows exist).
    op.drop_constraint("ck_iptables_action", "iptables_rules", type_="check")
    op.create_check_constraint(
        "ck_iptables_action",
        "iptables_rules",
        "action IN ('ACCEPT', 'DROP', 'REJECT')",
    )

    # 4. Restore narrow chain constraint (will fail if POSTROUTING rows exist).
    op.drop_constraint("ck_iptables_chain", "iptables_rules", type_="check")
    op.create_check_constraint(
        "ck_iptables_chain",
        "iptables_rules",
        "chain IN ('INPUT', 'FORWARD', 'OUTPUT')",
    )

    # 5. Remove rule_table value constraint.
    op.drop_constraint("ck_iptables_rule_table", "iptables_rules", type_="check")

    # 6. Restore original unique partial index (without rule_table / to_source).
    op.create_index(
        "idx_iptables_unique_rule",
        "iptables_rules",
        ["tunnel_id", "chain", "protocol", "source_cidr", "dest_cidr", "dport", "action"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # 7. Remove columns.
    op.drop_column("iptables_rules", "to_source")
    op.drop_column("iptables_rules", "rule_table")
