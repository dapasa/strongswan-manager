"""Add packet_captures table and capture audit actions.

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-27
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "packet_captures",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("server_id", sa.BigInteger(), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("mode", sa.Text(), nullable=False),
        sa.Column("interface", sa.Text(), nullable=False),
        sa.Column("host_filter", sa.Text(), nullable=True),
        sa.Column("port_filter", sa.Integer(), nullable=True),
        sa.Column("protocol_filter", sa.Text(), nullable=False, server_default="all"),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("snaplen", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="running"),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("s3_object_key", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("mode IN ('headers', 'full')", name="ck_captures_mode"),
        sa.CheckConstraint(
            "protocol_filter IN ('tcp', 'udp', 'icmp', 'all')",
            name="ck_captures_protocol",
        ),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'deleted')",
            name="ck_captures_status",
        ),
        sa.CheckConstraint(
            "port_filter IS NULL OR port_filter BETWEEN 1 AND 65535",
            name="ck_captures_port",
        ),
        sa.CheckConstraint("duration_seconds > 0", name="ck_captures_duration_pos"),
        sa.CheckConstraint("snaplen >= 0", name="ck_captures_snaplen"),
    )
    op.create_index("idx_captures_server_id", "packet_captures", ["server_id"])
    op.create_index("idx_captures_user_id", "packet_captures", ["user_id"])
    op.create_index(
        "idx_captures_server_running",
        "packet_captures",
        ["server_id", "status"],
        postgresql_where=sa.text("status = 'running' AND deleted_at IS NULL"),
    )

    # Extend the audit_logs action check constraint to include capture actions.
    # Drop and recreate (PostgreSQL requires this for CHECK constraints). The list must
    # keep every action allowed by 0021, including the tunnel control ones from 0018.
    op.drop_constraint("ck_audit_action", "audit_logs")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ("
        "'create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'revoke_sessions',"
        " 'initiate', 'terminate',"
        " 'access_request', 'access_grant', 'access_revoke', 'access_reject', 'access_invalid',"
        " 'capture_start', 'capture_view', 'capture_delete'"
        ")",
    )


def downgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs")
    op.create_check_constraint(
        "ck_audit_action",
        "audit_logs",
        "action IN ("
        "'create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'revoke_sessions',"
        " 'initiate', 'terminate',"
        " 'access_request', 'access_grant', 'access_revoke', 'access_reject', 'access_invalid'"
        ")",
    )
    op.drop_index("idx_captures_server_running", table_name="packet_captures")
    op.drop_index("idx_captures_user_id", table_name="packet_captures")
    op.drop_index("idx_captures_server_id", table_name="packet_captures")
    op.drop_table("packet_captures")
