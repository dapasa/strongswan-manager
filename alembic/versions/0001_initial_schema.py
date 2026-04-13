"""Initial schema — all 6 tables.

Revision ID: 0001
Revises:
Create Date: 2026-04-10

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable uuid-ossp extension for gen_random_uuid()
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("sub", sa.Text, nullable=False),
        sa.Column("email", sa.Text, nullable=False),
        sa.Column("display_name", sa.Text, nullable=True),
        sa.Column("role", sa.Text, nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("sub", name="uq_users_sub"),
        sa.CheckConstraint("role IN ('admin', 'viewer')", name="ck_users_role"),
    )
    op.create_index("idx_users_email", "users", ["email"])

    # --- tunnels ---
    op.create_table(
        "tunnels",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("peer_ip", postgresql.INET, nullable=False),
        sa.Column("local_cidrs", postgresql.ARRAY(postgresql.CIDR), nullable=False),
        sa.Column("remote_cidrs", postgresql.ARRAY(postgresql.CIDR), nullable=False),
        sa.Column("psk_secret_name", sa.Text, nullable=False),
        sa.Column("ike_version", sa.Text, nullable=False, server_default="2"),
        sa.Column("ike_proposals", sa.Text, nullable=True),
        sa.Column("esp_proposals", sa.Text, nullable=True),
        sa.Column("dpd_action", sa.Text, server_default="restart"),
        sa.Column("dpd_delay", sa.Integer, server_default=sa.text("30")),
        sa.Column("dpd_timeout", sa.Integer, server_default=sa.text("150")),
        sa.Column("status", sa.Text, nullable=False, server_default="active"),
        sa.Column("sync_status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("sync_error", sa.Text, nullable=True),
        sa.Column("created_by", sa.BigInteger, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("ike_version IN ('1', '2')", name="ck_tunnels_ike_version"),
        sa.CheckConstraint("status IN ('active', 'inactive')", name="ck_tunnels_status"),
        sa.CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
            name="ck_tunnels_sync_status",
        ),
        sa.CheckConstraint("dpd_action IN ('none', 'clear', 'restart')", name="ck_tunnels_dpd_action"),
    )
    op.create_index(
        "idx_tunnels_name_active",
        "tunnels",
        ["name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index("idx_tunnels_status", "tunnels", ["status"])
    op.create_index(
        "idx_tunnels_sync_status",
        "tunnels",
        ["sync_status"],
        postgresql_where=sa.text("sync_status != 'synced'"),
    )
    op.create_index("idx_tunnels_created_by", "tunnels", ["created_by"])

    # --- routes ---
    op.create_table(
        "routes",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tunnel_id", sa.BigInteger, sa.ForeignKey("tunnels.id"), nullable=False),
        sa.Column("cidr", postgresql.CIDR, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("sync_status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("sync_error", sa.Text, nullable=True),
        sa.Column("created_by", sa.BigInteger, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
            name="ck_routes_sync_status",
        ),
    )
    op.create_index(
        "idx_routes_tunnel_cidr_active",
        "routes",
        ["tunnel_id", "cidr"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index("idx_routes_tunnel_id", "routes", ["tunnel_id"])
    op.create_index(
        "idx_routes_sync_status",
        "routes",
        ["sync_status"],
        postgresql_where=sa.text("sync_status != 'synced'"),
    )

    # --- iptables_rules ---
    op.create_table(
        "iptables_rules",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tunnel_id", sa.BigInteger, sa.ForeignKey("tunnels.id"), nullable=False),
        sa.Column("chain", sa.Text, nullable=False),
        sa.Column("protocol", sa.Text, nullable=False),
        sa.Column("source_cidr", postgresql.CIDR, nullable=True),
        sa.Column("dest_cidr", postgresql.CIDR, nullable=True),
        sa.Column("sport", sa.Integer, nullable=True),
        sa.Column("dport", sa.Integer, nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("state_match", postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("comment", sa.Text, nullable=True),
        sa.Column("position", sa.Integer, nullable=True),
        sa.Column("sync_status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("sync_error", sa.Text, nullable=True),
        sa.Column("created_by", sa.BigInteger, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("chain IN ('INPUT', 'FORWARD', 'OUTPUT')", name="ck_iptables_chain"),
        sa.CheckConstraint("protocol IN ('tcp', 'udp', 'icmp', 'all')", name="ck_iptables_protocol"),
        sa.CheckConstraint("action IN ('ACCEPT', 'DROP', 'REJECT')", name="ck_iptables_action"),
        sa.CheckConstraint("sport BETWEEN 1 AND 65535", name="ck_iptables_sport"),
        sa.CheckConstraint("dport BETWEEN 1 AND 65535", name="ck_iptables_dport"),
        sa.CheckConstraint(
            "state_match <@ ARRAY['NEW', 'ESTABLISHED', 'RELATED', 'INVALID']::TEXT[]",
            name="ck_iptables_state_match",
        ),
        sa.CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
            name="ck_iptables_sync_status",
        ),
    )
    op.create_index("idx_iptables_tunnel_id", "iptables_rules", ["tunnel_id"])
    op.create_index(
        "idx_iptables_sync_status",
        "iptables_rules",
        ["sync_status"],
        postgresql_where=sa.text("sync_status != 'synced'"),
    )
    op.create_index(
        "idx_iptables_unique_rule",
        "iptables_rules",
        ["tunnel_id", "chain", "protocol", "source_cidr", "dest_cidr", "dport", "action"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # --- async_operations ---
    op.create_table(
        "async_operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("entity_id", sa.BigInteger, nullable=False),
        sa.Column("operation", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_by", sa.BigInteger, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("entity_type IN ('route')", name="ck_async_ops_entity_type"),
        sa.CheckConstraint("operation IN ('create', 'update', 'delete')", name="ck_async_ops_operation"),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_async_ops_status",
        ),
    )
    op.create_index("idx_async_ops_entity", "async_operations", ["entity_type", "entity_id"])
    op.create_index(
        "idx_async_ops_status",
        "async_operations",
        ["status"],
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )

    # --- audit_logs ---
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.BigInteger, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("entity_id", sa.BigInteger, nullable=True),
        sa.Column("previous_state", postgresql.JSONB, nullable=True),
        sa.Column("new_state", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", postgresql.INET, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "action IN ('create', 'update', 'delete', 'retry', 'login')",
            name="ck_audit_action",
        ),
    )
    op.create_index("idx_audit_entity", "audit_logs", ["entity_type", "entity_id"])
    op.create_index("idx_audit_user", "audit_logs", ["user_id"])
    op.create_index("idx_audit_created", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("async_operations")
    op.drop_table("iptables_rules")
    op.drop_table("routes")
    op.drop_table("tunnels")
    op.drop_table("users")
    op.execute('DROP EXTENSION IF EXISTS "uuid-ossp"')
