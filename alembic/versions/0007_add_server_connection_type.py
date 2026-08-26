"""Add dual-transport support to servers: connection_type, SSM fields, nullable SSH columns.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-26

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add connection_type with default 'ssh' so existing rows satisfy NOT NULL
    op.add_column("servers", sa.Column("connection_type", sa.Text(), nullable=True))
    op.execute("UPDATE servers SET connection_type = 'ssh'")
    op.alter_column("servers", "connection_type", nullable=False)

    # 2. Add SSM-specific nullable columns
    op.add_column("servers", sa.Column("ec2_instance_id", sa.Text(), nullable=True))
    op.add_column("servers", sa.Column("aws_role_arn", sa.Text(), nullable=True))
    op.add_column("servers", sa.Column("aws_region_override", sa.Text(), nullable=True))

    # 3. Make SSH fields nullable (they were NOT NULL before)
    op.alter_column("servers", "hostname", nullable=True)
    op.alter_column("servers", "ssh_user", nullable=True)
    op.alter_column("servers", "ssh_private_key_encrypted", nullable=True)

    # 4. Drop old ssh_port constraint and make column nullable
    #    Constraint name from migration 0005: ck_servers_ssh_port
    op.drop_constraint("ck_servers_ssh_port", "servers", type_="check")
    op.alter_column("servers", "ssh_port", nullable=True)
    op.create_check_constraint(
        "ck_servers_ssh_port",
        "servers",
        "ssh_port IS NULL OR ssh_port BETWEEN 1 AND 65535",
    )

    # 5. connection_type enum constraint
    op.create_check_constraint(
        "ck_servers_connection_type",
        "servers",
        "connection_type IN ('ssh', 'ssm')",
    )

    # 6. ec2_instance_id format constraint
    op.create_check_constraint(
        "ck_servers_ec2_instance_id_fmt",
        "servers",
        "ec2_instance_id IS NULL OR ec2_instance_id ~ '^i-[0-9a-f]{17}$'",
    )

    # 7. Coherence constraint: SSH requires key+user+hostname; SSM requires instance id
    op.create_check_constraint(
        "ck_servers_transport_fields",
        "servers",
        "(connection_type = 'ssh' AND ssh_private_key_encrypted IS NOT NULL "
        " AND ssh_user IS NOT NULL AND hostname IS NOT NULL) "
        "OR (connection_type = 'ssm' AND ec2_instance_id IS NOT NULL)",
    )


def downgrade() -> None:
    # Remove constraints added in upgrade
    op.drop_constraint("ck_servers_transport_fields", "servers", type_="check")
    op.drop_constraint("ck_servers_ec2_instance_id_fmt", "servers", type_="check")
    op.drop_constraint("ck_servers_connection_type", "servers", type_="check")
    op.drop_constraint("ck_servers_ssh_port", "servers", type_="check")

    # Restore ssh_port constraint (original: NOT NULL with range check)
    op.alter_column("servers", "ssh_port", nullable=False)
    op.create_check_constraint(
        "ck_servers_ssh_port",
        "servers",
        "ssh_port BETWEEN 1 AND 65535",
    )

    # Restore SSH columns to NOT NULL
    # (Assumes all existing rows are 'ssh' with valid data — true for a clean downgrade)
    op.alter_column("servers", "ssh_private_key_encrypted", nullable=False)
    op.alter_column("servers", "ssh_user", nullable=False)
    op.alter_column("servers", "hostname", nullable=False)

    # Drop SSM and connection_type columns
    op.drop_column("servers", "aws_region_override")
    op.drop_column("servers", "aws_role_arn")
    op.drop_column("servers", "ec2_instance_id")
    op.drop_column("servers", "connection_type")
