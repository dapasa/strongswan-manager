from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin


class User(TimestampMixin, Base):
    """OIDC-authenticated user with RBAC role."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sub: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(Text, nullable=False, server_default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    tunnels: Mapped[list[Tunnel]] = relationship(back_populates="creator", lazy="noload")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user", lazy="noload")

    __table_args__ = (
        CheckConstraint("role IN ('admin', 'operator', 'viewer')", name="ck_users_role"),
        Index("idx_users_email", "email"),
    )


class Tunnel(TimestampMixin, SoftDeleteMixin, Base):
    """IPSec tunnel configuration."""

    __tablename__ = "tunnels"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    peer_ip: Mapped[str] = mapped_column(INET, nullable=False)
    local_cidrs: Mapped[list[str]] = mapped_column(ARRAY(CIDR), nullable=False)
    remote_cidrs: Mapped[list[str]] = mapped_column(ARRAY(CIDR), nullable=False)
    ike_version: Mapped[str] = mapped_column(Text, nullable=False, server_default="2")
    ike_proposals: Mapped[str | None] = mapped_column(Text, nullable=True)
    esp_proposals: Mapped[str | None] = mapped_column(Text, nullable=True)
    dpd_action: Mapped[str] = mapped_column(Text, server_default="restart")
    dpd_delay: Mapped[int] = mapped_column(Integer, server_default=text("30"))
    dpd_timeout: Mapped[int] = mapped_column(Integer, server_default=text("150"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    sync_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    psk_secret_name: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    # Relationships
    creator: Mapped[User | None] = relationship(back_populates="tunnels", lazy="noload")
    routes: Mapped[list[Route]] = relationship(back_populates="tunnel", lazy="selectin")
    iptables_rules: Mapped[list[IPTablesRule]] = relationship(back_populates="tunnel", lazy="selectin")

    __table_args__ = (
        CheckConstraint("ike_version IN ('1', '2')", name="ck_tunnels_ike_version"),
        CheckConstraint("status IN ('active', 'inactive', 'up', 'down', 'unknown')", name="ck_tunnels_status"),
        CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete', 'partial')",
            name="ck_tunnels_sync_status",
        ),
        CheckConstraint("dpd_action IN ('none', 'clear', 'restart')", name="ck_tunnels_dpd_action"),
        Index(
            "idx_tunnels_name_active",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("idx_tunnels_status", "status"),
        Index(
            "idx_tunnels_sync_status",
            "sync_status",
            postgresql_where=text("sync_status != 'synced'"),
        ),
        Index("idx_tunnels_created_by", "created_by"),
    )


class Route(TimestampMixin, SoftDeleteMixin, Base):
    """Static route managed via Terragrunt for a tunnel."""

    __tablename__ = "routes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tunnels.id"), nullable=False)
    cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    # Relationships
    tunnel: Mapped[Tunnel] = relationship(back_populates="routes", lazy="noload")

    __table_args__ = (
        CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete', 'cloning', 'planning', 'applying', 'pushing')",
            name="ck_routes_sync_status",
        ),
        Index(
            "idx_routes_tunnel_cidr_active",
            "tunnel_id",
            "cidr",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("idx_routes_tunnel_id", "tunnel_id"),
        Index(
            "idx_routes_sync_status",
            "sync_status",
            postgresql_where=text("sync_status != 'synced'"),
        ),
    )


class IPTablesRule(TimestampMixin, SoftDeleteMixin, Base):
    """Structured iptables rule applied via SSM to VPN instances."""

    __tablename__ = "iptables_rules"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tunnels.id"), nullable=False)
    chain: Mapped[str] = mapped_column(Text, nullable=False)
    protocol: Mapped[str] = mapped_column(Text, nullable=False)
    source_cidr: Mapped[str | None] = mapped_column(CIDR, nullable=True)
    dest_cidr: Mapped[str | None] = mapped_column(CIDR, nullable=True)
    sport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    state_match: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    position: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sync_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    # Relationships
    tunnel: Mapped[Tunnel] = relationship(back_populates="iptables_rules", lazy="noload")

    __table_args__ = (
        CheckConstraint("chain IN ('INPUT', 'FORWARD', 'OUTPUT')", name="ck_iptables_chain"),
        CheckConstraint("protocol IN ('tcp', 'udp', 'icmp', 'all')", name="ck_iptables_protocol"),
        CheckConstraint("action IN ('ACCEPT', 'DROP', 'REJECT')", name="ck_iptables_action"),
        CheckConstraint("sport BETWEEN 1 AND 65535", name="ck_iptables_sport"),
        CheckConstraint("dport BETWEEN 1 AND 65535", name="ck_iptables_dport"),
        CheckConstraint(
            "state_match <@ ARRAY['NEW', 'ESTABLISHED', 'RELATED', 'INVALID']::TEXT[]",
            name="ck_iptables_state_match",
        ),
        CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
            name="ck_iptables_sync_status",
        ),
        Index("idx_iptables_tunnel_id", "tunnel_id"),
        Index(
            "idx_iptables_sync_status",
            "sync_status",
            postgresql_where=text("sync_status != 'synced'"),
        ),
        Index(
            "idx_iptables_unique_rule",
            "tunnel_id",
            "chain",
            "protocol",
            "source_cidr",
            "dest_cidr",
            "dport",
            "action",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class Server(TimestampMixin, SoftDeleteMixin, Base):
    """VPN server supporting SSH or SSM transport for connectivity and config push."""

    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # Transport selector — editable after creation
    connection_type: Mapped[str] = mapped_column(Text, nullable=False, server_default="ssh")
    # SSH transport fields (nullable for SSM servers)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssh_port: Mapped[int | None] = mapped_column(Integer, nullable=True, server_default=text("22"))
    ssh_user: Mapped[str | None] = mapped_column(Text, nullable=True, server_default="admin")
    ssh_private_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    # SSM transport fields
    ec2_instance_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    aws_role_arn: Mapped[str | None] = mapped_column(Text, nullable=True)       # NULL → use global
    aws_region_override: Mapped[str | None] = mapped_column(Text, nullable=True)  # NULL → use global
    # Common fields
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "last_check_status IN ('reachable', 'unreachable')",
            name="ck_servers_check_status",
        ),
        CheckConstraint(
            "ssh_port IS NULL OR ssh_port BETWEEN 1 AND 65535",
            name="ck_servers_ssh_port",
        ),
        CheckConstraint(
            "connection_type IN ('ssh', 'ssm')",
            name="ck_servers_connection_type",
        ),
        CheckConstraint(
            "ec2_instance_id IS NULL OR ec2_instance_id ~ '^i-[0-9a-f]{17}$'",
            name="ck_servers_ec2_instance_id_fmt",
        ),
        CheckConstraint(
            "(connection_type = 'ssh' AND ssh_private_key_encrypted IS NOT NULL"
            " AND ssh_user IS NOT NULL AND hostname IS NOT NULL)"
            " OR (connection_type = 'ssm' AND ec2_instance_id IS NOT NULL)",
            name="ck_servers_transport_fields",
        ),
        Index(
            "idx_servers_name_active",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class AsyncOperation(TimestampMixin, Base):
    """Tracks async background operations (route create/delete via Terragrunt)."""

    __tablename__ = "async_operations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    operation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        CheckConstraint("entity_type IN ('route')", name="ck_async_ops_entity_type"),
        CheckConstraint("operation IN ('create', 'update', 'delete')", name="ck_async_ops_operation"),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_async_ops_status",
        ),
        Index("idx_async_ops_entity", "entity_type", "entity_id"),
        Index(
            "idx_async_ops_status",
            "status",
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
    )


class AuditLog(Base):
    """Immutable audit trail for all CUD operations."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    previous_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    new_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    user: Mapped[User | None] = relationship(back_populates="audit_logs", lazy="noload")

    __table_args__ = (
        CheckConstraint(
            "action IN ('create', 'update', 'delete', 'retry', 'login')",
            name="ck_audit_action",
        ),
        Index("idx_audit_entity", "entity_type", "entity_id"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_created", "created_at"),
    )
