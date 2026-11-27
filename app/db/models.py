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
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin

# ---------------------------------------------------------------------------
# Tier 1 — permission keys that can be granted per-user
# ---------------------------------------------------------------------------
TIER1_PERMISSION_KEYS = (
    "tunnels.write",
    "tunnels.connect",
    "tunnels.psk",
    "routes.write",
    "iptables.filter",
    "iptables.snat",
    "capture.headers",
)

# SQL literal for the check constraint
_T1_KEYS_SQL = ", ".join(f"'{k}'" for k in TIER1_PERMISSION_KEYS)

# ---------------------------------------------------------------------------
# Tier 2 — access-request permission keys (time-limited, Shortcut-approved)
# ---------------------------------------------------------------------------
TIER2_PERMISSION_KEYS = ("capture.full",)
_T2_KEYS_SQL = ", ".join(f"'{k}'" for k in TIER2_PERMISSION_KEYS)

# Access-request final statuses (no further polling)
ACCESS_REQUEST_FINAL_STATUSES = ("rejected", "invalid", "revoked", "expired")


class User(TimestampMixin, Base):
    """Authenticated user with RBAC role.

    In local auth mode (AUTH_MODE=local), ``sub`` is set to ``"local:<email>"``
    and ``password_hash`` stores the bcrypt hash.  In OIDC mode, ``sub`` comes
    from the IdP and ``password_hash`` is NULL.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sub: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(Text, nullable=False, server_default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    # When set, tokens whose iat (issued-at) is earlier than this value are rejected.
    # Set by revoke-sessions / logout-all to invalidate all outstanding tokens.
    tokens_valid_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Shortcut member UUID — required to create a Tier 2 access request.
    shortcut_member_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    tunnels: Mapped[list[Tunnel]] = relationship(back_populates="creator", lazy="noload")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user", lazy="noload")
    tier1_permissions: Mapped[list[UserPermission]] = relationship(
        back_populates="user",
        lazy="noload",
        cascade="all, delete-orphan",
    )
    access_requests: Mapped[list[AccessRequest]] = relationship(
        back_populates="user",
        lazy="noload",
    )

    __table_args__ = (
        CheckConstraint("role IN ('admin', 'operator', 'viewer')", name="ck_users_role"),
        Index("idx_users_email", "email"),
    )


class UserPermission(TimestampMixin, Base):
    """Tier 1 per-user permission grant.

    Operators receive none by default.  An admin explicitly assigns permissions.
    Admin users always have every Tier 1 permission implicitly (no DB row needed).
    """

    __tablename__ = "user_permissions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    permission_key: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationship
    user: Mapped[User] = relationship(back_populates="tier1_permissions", lazy="noload")

    __table_args__ = (
        CheckConstraint(
            f"permission_key IN ({_T1_KEYS_SQL})",
            name="ck_user_permissions_key",
        ),
        UniqueConstraint("user_id", "permission_key", name="uq_user_permissions"),
        Index("idx_user_permissions_user_id", "user_id"),
    )


class AccessRequest(TimestampMixin, Base):
    """Tier 2 time-limited elevated access request, approved via Shortcut.

    Status transitions (non-final → final):
      requested → active  (approved by an authorized lead, not the requester)
      requested → rejected (card moved to Rejected/Completed before approval)
      requested / active → invalid  (approver not in lead list, or was the requester)
      active → revoked  (card leaves Approved or is gone)
      active → expired  (expires_at passed)
    """

    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    permission_key: Mapped[str] = mapped_column(Text, nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    # Shortcut story ID and URL set once the card is created
    shortcut_story_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    shortcut_story_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Status lifecycle
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="requested")
    approved_by_member_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Human-readable reason for rejection / revocation / invalid approval
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationship
    user: Mapped[User] = relationship(back_populates="access_requests", lazy="noload")

    __table_args__ = (
        CheckConstraint(
            f"permission_key IN ({_T2_KEYS_SQL})",
            name="ck_access_requests_permission_key",
        ),
        CheckConstraint(
            "status IN ('requested', 'active', 'rejected', 'invalid', 'revoked', 'expired')",
            name="ck_access_requests_status",
        ),
        CheckConstraint("duration_seconds > 0", name="ck_access_requests_duration_pos"),
        Index("idx_access_requests_user_id", "user_id"),
        Index(
            "idx_access_requests_active",
            "status",
            postgresql_where=text("status IN ('requested', 'active')"),
        ),
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
    # psk_secret_name kept nullable for migration compatibility (previously pointed to S3 path).
    # New tunnels leave this NULL; the PSK is now stored encrypted in psk_encrypted.
    psk_secret_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    # KMS-encrypted PSK, base64-encoded (set on create/update, decrypted only when pushing config).
    psk_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Timestamp of last PSK set (create, update with new PSK, or rotate-psk). Never stores the PSK.
    psk_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # IKE identity for the local side (e.g. the node's EIP). When null,
    # strongSwan uses the source IP automatically. Renders as leftid (stroke)
    # or local { id = ... } (swanctl) — omitted entirely when null.
    local_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    # IKE identity the remote peer presents. When null, falls back to peer_ip.
    remote_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Controls how the child SA is initiated: 'trap' (route-based, waits for traffic),
    # 'none' (passive, waits for peer to initiate), 'start' (initiates immediately).
    start_action: Mapped[str] = mapped_column(Text, nullable=False, server_default="trap")
    # IKE SA lifetime in seconds. Hardcoded as 86400 previously; now configurable.
    ike_lifetime: Mapped[int] = mapped_column(Integer, server_default=text("86400"))
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
        CheckConstraint("start_action IN ('trap', 'none', 'start')", name="ck_tunnels_start_action"),
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
    """VPC route for a tunnel — managed via the AWS EC2 API (sc-31774)."""

    __tablename__ = "routes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tunnels.id"), nullable=False)
    cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ENI targeted by this route (resolved from EIP holder at creation time)
    target_eni: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Per-route-table outcome: {rtb_id: {"status": "ok"|"failed"|"already_exists_same_target", "error": "..."}}
    table_outcomes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    # Relationships
    tunnel: Mapped[Tunnel] = relationship(back_populates="routes", lazy="noload")

    __table_args__ = (
        CheckConstraint(
            "sync_status IN ('synced', 'pending', 'failed', 'pending_delete')",
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
    """Structured iptables rule applied via SSM to VPN instances.

    Supports two rule families:
    - filter (default): chain in INPUT/FORWARD/OUTPUT, action in ACCEPT/DROP/REJECT
    - nat (SNAT): chain=POSTROUTING, action=SNAT, requires to_source (the public IP)
    """

    __tablename__ = "iptables_rules"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tunnels.id"), nullable=False)
    # iptables table: 'filter' (default) or 'nat' (for SNAT rules).
    rule_table: Mapped[str] = mapped_column(Text, nullable=False, server_default="filter", default="filter")
    chain: Mapped[str] = mapped_column(Text, nullable=False)
    protocol: Mapped[str] = mapped_column(Text, nullable=False)
    source_cidr: Mapped[str | None] = mapped_column(CIDR, nullable=True)
    dest_cidr: Mapped[str | None] = mapped_column(CIDR, nullable=True)
    sport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    # SNAT target IP (--to-source). Required when rule_table='nat', NULL otherwise.
    to_source: Mapped[str | None] = mapped_column(INET, nullable=True)
    state_match: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    position: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sync_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    # Relationships
    tunnel: Mapped[Tunnel] = relationship(back_populates="iptables_rules", lazy="noload")

    __table_args__ = (
        CheckConstraint(
            "rule_table IN ('filter', 'nat')",
            name="ck_iptables_rule_table",
        ),
        CheckConstraint(
            "chain IN ('INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING')",
            name="ck_iptables_chain",
        ),
        CheckConstraint("protocol IN ('tcp', 'udp', 'icmp', 'all')", name="ck_iptables_protocol"),
        CheckConstraint(
            "action IN ('ACCEPT', 'DROP', 'REJECT', 'SNAT')",
            name="ck_iptables_action",
        ),
        # Consistency: filter rules cannot have to_source; nat/SNAT rules require it.
        CheckConstraint(
            "(rule_table = 'filter' AND chain IN ('INPUT', 'FORWARD', 'OUTPUT')"
            " AND action IN ('ACCEPT', 'DROP', 'REJECT') AND to_source IS NULL)"
            " OR (rule_table = 'nat' AND chain = 'POSTROUTING'"
            " AND action = 'SNAT' AND to_source IS NOT NULL)",
            name="ck_iptables_nat_consistency",
        ),
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
            "rule_table",
            "chain",
            "protocol",
            "source_cidr",
            "dest_cidr",
            "dport",
            "action",
            "to_source",
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
    # IPsec engine: 'stroke' (legacy ipsec daemon) or 'swanctl' (vici-based)
    ipsec_engine: Mapped[str] = mapped_column(Text, nullable=False, server_default="stroke")
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
            "ipsec_engine IN ('swanctl', 'stroke')",
            name="ck_servers_ipsec_engine",
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
    """Tracks async background operations (history of the removed Terragrunt route flow)."""

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


class PacketCapture(TimestampMixin, Base):
    """Packet capture record — one entry per capture session on a VPN node."""

    __tablename__ = "packet_captures"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("servers.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    mode: Mapped[str] = mapped_column(Text, nullable=False)  # 'headers' | 'full'
    interface: Mapped[str] = mapped_column(Text, nullable=False)  # e.g. 'ens5'
    host_filter: Mapped[str | None] = mapped_column(Text, nullable=True)   # validated IP/CIDR
    port_filter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol_filter: Mapped[str] = mapped_column(Text, nullable=False, server_default="all")
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    snaplen: Mapped[int] = mapped_column(Integer, nullable=False)  # 96=headers, 0=full
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="running")
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    s3_object_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Soft-delete for the capture record (the S3 object is deleted separately)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        CheckConstraint("mode IN ('headers', 'full')", name="ck_captures_mode"),
        CheckConstraint(
            "protocol_filter IN ('tcp', 'udp', 'icmp', 'all')",
            name="ck_captures_protocol",
        ),
        CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'deleted')",
            name="ck_captures_status",
        ),
        CheckConstraint(
            "port_filter IS NULL OR port_filter BETWEEN 1 AND 65535",
            name="ck_captures_port",
        ),
        CheckConstraint("duration_seconds > 0", name="ck_captures_duration_pos"),
        CheckConstraint("snaplen >= 0", name="ck_captures_snaplen"),
        Index("idx_captures_server_id", "server_id"),
        Index("idx_captures_user_id", "user_id"),
        Index(
            "idx_captures_server_running",
            "server_id",
            "status",
            postgresql_where=text("status = 'running' AND deleted_at IS NULL"),
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
            "action IN ("
            "'create', 'update', 'delete', 'retry', 'login', 'rotate_psk', 'revoke_sessions',"
            " 'access_request', 'access_grant', 'access_revoke', 'access_reject', 'access_invalid',"
            " 'capture_start', 'capture_view', 'capture_delete'"
            ")",
            name="ck_audit_action",
        ),
        Index("idx_audit_entity", "entity_type", "entity_id"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_created", "created_at"),
    )
