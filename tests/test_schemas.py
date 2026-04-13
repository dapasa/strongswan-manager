"""Tests for Pydantic schemas — pure validation, no DB required."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import pytest
from pydantic import ValidationError

from app.schemas.common import PaginationParams, ErrorResponse, HealthResponse
from app.schemas.dashboard import DashboardSummary
from app.schemas.iptables import IPTablesRuleCreate, IPTablesRuleUpdate
from app.schemas.route import RouteCreate
from app.schemas.tunnel import TunnelCreate, TunnelUpdate
from app.schemas.user import UserCreate, UserUpdate


# ---------------------------------------------------------------------------
# TunnelCreate
# ---------------------------------------------------------------------------


def test_tunnel_create_valid():
    t = TunnelCreate(
        name="prod-tunnel",
        peer_ip="203.0.113.1",
        local_cidrs=["10.0.0.0/24"],
        remote_cidrs=["192.168.1.0/24"],
        psk_secret_name="vpn/prod-psk",
    )
    assert t.name == "prod-tunnel"
    assert t.peer_ip == IPv4Address("203.0.113.1")
    assert t.ike_version == "2"
    assert t.dpd_action == "restart"
    assert t.dpd_delay == 30
    assert t.dpd_timeout == 150


def test_tunnel_create_missing_name():
    with pytest.raises(ValidationError) as exc_info:
        TunnelCreate(
            peer_ip="203.0.113.1",
            local_cidrs=["10.0.0.0/24"],
            remote_cidrs=["192.168.1.0/24"],
            psk_secret_name="vpn/psk",
        )
    assert "name" in str(exc_info.value)


def test_tunnel_create_empty_name():
    with pytest.raises(ValidationError):
        TunnelCreate(
            name="",
            peer_ip="203.0.113.1",
            local_cidrs=["10.0.0.0/24"],
            remote_cidrs=["192.168.1.0/24"],
            psk_secret_name="vpn/psk",
        )


def test_tunnel_create_invalid_peer_ip():
    with pytest.raises(ValidationError):
        TunnelCreate(
            name="test",
            peer_ip="not-an-ip",
            local_cidrs=["10.0.0.0/24"],
            remote_cidrs=["192.168.1.0/24"],
            psk_secret_name="vpn/psk",
        )


def test_tunnel_create_empty_cidrs():
    with pytest.raises(ValidationError):
        TunnelCreate(
            name="test",
            peer_ip="203.0.113.1",
            local_cidrs=[],
            remote_cidrs=["192.168.1.0/24"],
            psk_secret_name="vpn/psk",
        )


def test_tunnel_create_invalid_cidr():
    with pytest.raises(ValidationError):
        TunnelCreate(
            name="test",
            peer_ip="203.0.113.1",
            local_cidrs=["not-a-cidr"],
            remote_cidrs=["192.168.1.0/24"],
            psk_secret_name="vpn/psk",
        )


def test_tunnel_create_invalid_ike_version():
    with pytest.raises(ValidationError):
        TunnelCreate(
            name="test",
            peer_ip="203.0.113.1",
            local_cidrs=["10.0.0.0/24"],
            remote_cidrs=["192.168.1.0/24"],
            psk_secret_name="vpn/psk",
            ike_version="3",
        )


# ---------------------------------------------------------------------------
# TunnelUpdate
# ---------------------------------------------------------------------------


def test_tunnel_update_partial():
    t = TunnelUpdate(name="new-name")
    assert t.name == "new-name"
    assert t.peer_ip is None
    assert t.local_cidrs is None


def test_tunnel_update_empty():
    t = TunnelUpdate()
    assert t.name is None
    assert t.peer_ip is None


def test_tunnel_update_invalid_status():
    with pytest.raises(ValidationError):
        TunnelUpdate(status="deleted")


# ---------------------------------------------------------------------------
# RouteCreate
# ---------------------------------------------------------------------------


def test_route_create_valid():
    r = RouteCreate(cidr="172.16.0.0/16")
    assert r.cidr == IPv4Network("172.16.0.0/16")
    assert r.description is None


def test_route_create_with_description():
    r = RouteCreate(cidr="10.1.0.0/16", description="Office network")
    assert r.description == "Office network"


def test_route_create_invalid_cidr():
    with pytest.raises(ValidationError):
        RouteCreate(cidr="not-a-cidr")


def test_route_create_missing_cidr():
    with pytest.raises(ValidationError):
        RouteCreate()


# ---------------------------------------------------------------------------
# IPTablesRuleCreate
# ---------------------------------------------------------------------------


def test_iptables_create_valid_basic():
    rule = IPTablesRuleCreate(
        chain="FORWARD",
        protocol="tcp",
        dport=443,
        action="ACCEPT",
    )
    assert rule.chain == "FORWARD"
    assert rule.protocol == "tcp"
    assert rule.dport == 443
    assert rule.action == "ACCEPT"


def test_iptables_create_with_cidrs():
    rule = IPTablesRuleCreate(
        chain="FORWARD",
        protocol="all",
        source_cidr="10.0.0.0/8",
        dest_cidr="192.168.0.0/16",
        action="ACCEPT",
    )
    assert rule.source_cidr == IPv4Network("10.0.0.0/8")
    assert rule.dest_cidr == IPv4Network("192.168.0.0/16")


def test_iptables_create_port_requires_tcp_udp():
    with pytest.raises(ValidationError, match="sport/dport require protocol"):
        IPTablesRuleCreate(
            chain="FORWARD",
            protocol="icmp",
            dport=443,
            action="DROP",
        )


def test_iptables_create_port_with_all_protocol_fails():
    with pytest.raises(ValidationError, match="sport/dport require protocol"):
        IPTablesRuleCreate(
            chain="INPUT",
            protocol="all",
            sport=8080,
            action="ACCEPT",
        )


def test_iptables_create_port_with_tcp_ok():
    rule = IPTablesRuleCreate(
        chain="INPUT",
        protocol="tcp",
        sport=8080,
        dport=443,
        action="ACCEPT",
    )
    assert rule.sport == 8080
    assert rule.dport == 443


def test_iptables_create_comment_injection_semicolon():
    with pytest.raises(ValidationError, match="forbidden characters"):
        IPTablesRuleCreate(
            chain="FORWARD",
            protocol="tcp",
            action="ACCEPT",
            comment="legit; rm -rf /",
        )


def test_iptables_create_comment_injection_pipe():
    with pytest.raises(ValidationError, match="forbidden characters"):
        IPTablesRuleCreate(
            chain="FORWARD",
            protocol="tcp",
            action="ACCEPT",
            comment="legit | cat /etc/passwd",
        )


def test_iptables_create_comment_injection_backtick():
    with pytest.raises(ValidationError, match="forbidden characters"):
        IPTablesRuleCreate(
            chain="FORWARD",
            protocol="tcp",
            action="ACCEPT",
            comment="`whoami`",
        )


def test_iptables_create_valid_comment():
    rule = IPTablesRuleCreate(
        chain="FORWARD",
        protocol="tcp",
        action="ACCEPT",
        comment="Allow HTTPS from office",
    )
    assert rule.comment == "Allow HTTPS from office"


def test_iptables_create_state_match():
    rule = IPTablesRuleCreate(
        chain="FORWARD",
        protocol="all",
        action="ACCEPT",
        state_match=["NEW", "ESTABLISHED"],
    )
    assert rule.state_match == ["NEW", "ESTABLISHED"]


def test_iptables_create_invalid_chain():
    with pytest.raises(ValidationError):
        IPTablesRuleCreate(
            chain="PREROUTING",
            protocol="tcp",
            action="ACCEPT",
        )


def test_iptables_create_invalid_action():
    with pytest.raises(ValidationError):
        IPTablesRuleCreate(
            chain="FORWARD",
            protocol="tcp",
            action="MASQUERADE",
        )


def test_iptables_create_port_out_of_range():
    with pytest.raises(ValidationError):
        IPTablesRuleCreate(
            chain="FORWARD",
            protocol="tcp",
            dport=70000,
            action="ACCEPT",
        )


def test_iptables_update_comment_injection():
    with pytest.raises(ValidationError, match="forbidden characters"):
        IPTablesRuleUpdate(comment="bad$stuff")


# ---------------------------------------------------------------------------
# PaginationParams
# ---------------------------------------------------------------------------


def test_pagination_defaults():
    p = PaginationParams()
    assert p.page == 1
    assert p.page_size == 20


def test_pagination_custom():
    p = PaginationParams(page=3, page_size=50)
    assert p.page == 3
    assert p.page_size == 50


def test_pagination_page_zero():
    with pytest.raises(ValidationError):
        PaginationParams(page=0)


def test_pagination_negative_page():
    with pytest.raises(ValidationError):
        PaginationParams(page=-1)


def test_pagination_page_size_over_max():
    with pytest.raises(ValidationError):
        PaginationParams(page_size=101)


# ---------------------------------------------------------------------------
# UserCreate / UserUpdate
# ---------------------------------------------------------------------------


def test_user_create_valid():
    u = UserCreate(sub="oidc-123", email="user@example.com", display_name="Test")
    assert u.sub == "oidc-123"
    assert u.email == "user@example.com"


def test_user_create_missing_sub():
    with pytest.raises(ValidationError):
        UserCreate(email="user@example.com")


def test_user_create_empty_sub():
    with pytest.raises(ValidationError):
        UserCreate(sub="", email="user@example.com")


def test_user_update_valid_role():
    u = UserUpdate(role="admin")
    assert u.role == "admin"


def test_user_update_invalid_role():
    with pytest.raises(ValidationError):
        UserUpdate(role="superadmin")


def test_user_update_empty():
    u = UserUpdate()
    assert u.role is None
    assert u.is_active is None


# ---------------------------------------------------------------------------
# DashboardSummary
# ---------------------------------------------------------------------------


def test_dashboard_summary_valid():
    d = DashboardSummary(
        active_tunnels=5,
        active_routes=12,
        active_iptables_rules=8,
        failed_syncs=1,
        pending_operations=0,
        last_change=None,
    )
    assert d.active_tunnels == 5
    assert d.last_change is None


# ---------------------------------------------------------------------------
# ErrorResponse / HealthResponse
# ---------------------------------------------------------------------------


def test_error_response():
    e = ErrorResponse(detail="Not found", request_id="abc-123")
    assert e.detail == "Not found"
    assert e.request_id == "abc-123"


def test_health_response():
    h = HealthResponse(status="ok", checks={"db": "ok", "s3": "ok"})
    assert h.status == "ok"
    assert h.checks["db"] == "ok"
