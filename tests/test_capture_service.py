"""Tests for packet capture service — especially BPF injection prevention."""

from __future__ import annotations

import pytest

from app.schemas.capture import CaptureStart, HEADERS_SNAPLEN, FULL_SNAPLEN
from app.services.capture_service import build_bpf_filter, build_capture_script


# ---------------------------------------------------------------------------
# BPF filter tests
# ---------------------------------------------------------------------------

class TestBuildBpfFilter:
    def test_no_filter(self):
        result = build_bpf_filter(
            interface="ens5",
            host_filter=None,
            port_filter=None,
            protocol_filter="all",
        )
        assert result == ""

    def test_protocol_only(self):
        result = build_bpf_filter(
            interface="ens5",
            host_filter=None,
            port_filter=None,
            protocol_filter="tcp",
        )
        assert result == "tcp"

    def test_host_ip(self):
        result = build_bpf_filter(
            interface="ens5",
            host_filter="10.0.0.1",
            port_filter=None,
            protocol_filter="all",
        )
        assert result == "host 10.0.0.1"

    def test_host_cidr(self):
        result = build_bpf_filter(
            interface="ens5",
            host_filter="10.0.0.0/24",
            port_filter=None,
            protocol_filter="all",
        )
        assert result == "net 10.0.0.0/24"

    def test_port_only(self):
        result = build_bpf_filter(
            interface="ens5",
            host_filter=None,
            port_filter=443,
            protocol_filter="all",
        )
        assert result == "port 443"

    def test_full_combination(self):
        result = build_bpf_filter(
            interface="ens5",
            host_filter="192.168.1.1",
            port_filter=80,
            protocol_filter="tcp",
        )
        assert result == "tcp and host 192.168.1.1 and port 80"

    def test_invalid_interface_rejected(self):
        from app.exceptions import ValidationError
        with pytest.raises(ValidationError):
            build_bpf_filter(
                interface="eth0; rm -rf /",
                host_filter=None,
                port_filter=None,
                protocol_filter="all",
            )

    def test_udp_protocol(self):
        result = build_bpf_filter(
            interface="ens6",
            host_filter=None,
            port_filter=53,
            protocol_filter="udp",
        )
        assert result == "udp and port 53"

    def test_icmp_protocol(self):
        result = build_bpf_filter(
            interface="any",
            host_filter=None,
            port_filter=None,
            protocol_filter="icmp",
        )
        assert result == "icmp"

    def test_cidr_host_32(self):
        """A /32 CIDR should use 'host' not 'net'."""
        result = build_bpf_filter(
            interface="ens5",
            host_filter="10.0.0.5/32",
            port_filter=None,
            protocol_filter="all",
        )
        assert result == "host 10.0.0.5"


# ---------------------------------------------------------------------------
# Injection prevention tests — schema validation layer
# ---------------------------------------------------------------------------

class TestCaptureStartInjection:
    def test_invalid_interface_rejected_by_schema(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5; rm -rf /",
                duration_seconds=30,
            )

    def test_bpf_injection_in_host_rejected(self):
        """An injection attempt via host_filter must be rejected at schema validation."""
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=30,
                host_filter="10.0.0.1; echo pwned",
            )

    def test_bpf_injection_backtick_in_host_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=30,
                host_filter="`whoami`",
            )

    def test_bpf_injection_newline_in_host_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=30,
                host_filter="10.0.0.1\nrm -rf /",
            )

    def test_port_out_of_range_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=30,
                port_filter=99999,
            )

    def test_port_zero_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=30,
                port_filter=0,
            )

    def test_invalid_protocol_rejected_by_schema(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=30,
                protocol_filter="all; rm -rf /",
            )

    def test_duration_too_low_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CaptureStart(
                server_id=1,
                interface="ens5",
                duration_seconds=5,  # below ge=10
            )

    def test_valid_start_accepted(self):
        c = CaptureStart(
            server_id=1,
            interface="ens5",
            duration_seconds=60,
            mode="headers",
            host_filter="10.0.0.0/8",
            port_filter=443,
            protocol_filter="tcp",
        )
        assert c.interface == "ens5"
        assert c.host_filter == "10.0.0.0/8"
        assert c.port_filter == 443

    def test_full_mode_accepted(self):
        c = CaptureStart(
            server_id=2,
            interface="ens6",
            duration_seconds=120,
            mode="full",
        )
        assert c.mode == "full"

    def test_any_interface_accepted(self):
        c = CaptureStart(
            server_id=1,
            interface="any",
            duration_seconds=30,
        )
        assert c.interface == "any"


# ---------------------------------------------------------------------------
# Script builder tests — ensure injections don't survive shlex.quote
# ---------------------------------------------------------------------------

class TestBuildCaptureScript:
    def test_script_contains_trap(self):
        script = build_capture_script(
            capture_id=42,
            interface="ens5",
            bpf_filter="tcp",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://s3.example.com/presigned?sig=abc",
        )
        assert "trap" in script
        assert "rm -f" in script
        assert "EXIT" in script

    def test_script_uses_timeout(self):
        script = build_capture_script(
            capture_id=1,
            interface="ens5",
            bpf_filter="",
            duration_seconds=120,
            snaplen=96,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "timeout 120" in script

    def test_presigned_url_with_special_chars_is_quoted(self):
        """A presigned URL with & and = must be properly quoted."""
        url = "https://s3.amazonaws.com/bucket/key?X-Amz-Algorithm=AWS4&X-Amz-Credential=AKID"
        script = build_capture_script(
            capture_id=1,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=96,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url=url,
        )
        # The URL must appear quoted in the script
        import shlex
        assert shlex.quote(url) in script
        # The raw '&' must not appear unquoted
        assert " & " not in script

    def test_no_disk_write(self):
        """Script must use /dev/shm, not any disk path."""
        script = build_capture_script(
            capture_id=5,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=96,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "/dev/shm" in script
        assert "/tmp" not in script
        assert "/var" not in script

    def test_full_snaplen_zero(self):
        script = build_capture_script(
            capture_id=1,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=FULL_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "-s 0" in script

    def test_headers_snaplen(self):
        script = build_capture_script(
            capture_id=1,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert f"-s {HEADERS_SNAPLEN}" in script

    def test_bpf_filter_in_script(self):
        """BPF filter appears (quoted) when provided."""
        script = build_capture_script(
            capture_id=10,
            interface="ens5",
            bpf_filter="tcp and port 443",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        import shlex
        assert shlex.quote("tcp and port 443") in script

    def test_capture_id_in_tmpfile_path(self):
        """Temp file path includes the capture ID for uniqueness."""
        script = build_capture_script(
            capture_id=999,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=96,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "/dev/shm/capture_999.pcap" in script

    def test_size_check_in_script(self):
        """Script enforces size limit via ulimit -f (block count = max_size_bytes // 512)."""
        max_bytes = 52428800  # 50 MiB
        expected_blocks = max_bytes // 512  # 102400
        script = build_capture_script(
            capture_id=1,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=96,
            max_size_bytes=max_bytes,
            presigned_url="https://example.com/put",
        )
        assert f"ulimit -f {expected_blocks}" in script
        assert "SIZE" in script

    def test_script_contains_ulimit(self):
        """Script must set ulimit -f in a subshell before tcpdump."""
        script = build_capture_script(
            capture_id=7,
            interface="ens5",
            bpf_filter="",
            duration_seconds=60,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=10 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "ulimit -f" in script
        # ulimit must be in a subshell (parenthesised) so the limit applies to tcpdump only
        assert "( ulimit -f" in script

    def test_script_no_sudo(self):
        """tcpdump command must NOT use sudo (SSM runs as root; ulimit must be inherited)."""
        script = build_capture_script(
            capture_id=3,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "sudo" not in script

    def test_sigxfsz_handling(self):
        """RC=153 (SIGXFSZ) must be treated as a valid truncated capture, not an error."""
        script = build_capture_script(
            capture_id=8,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        # RC=153 must be in the allowed-RCs list
        assert "153" in script
        # Script must set TRUNCATED=1 when RC=153
        assert "TRUNCATED=1" in script
        # Script must echo TRUNCATED_BY_SIZE via the variable
        assert "TRUNCATED_BY_SIZE=$TRUNCATED" in script

    def test_curl_has_max_time(self):
        """curl upload must have --max-time to prevent indefinite hangs."""
        script = build_capture_script(
            capture_id=2,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "--max-time" in script

    def test_capture_size_echoed(self):
        """Script must echo CAPTURE_SIZE=<n> so the manager can parse file size from stdout."""
        script = build_capture_script(
            capture_id=4,
            interface="ens5",
            bpf_filter="",
            duration_seconds=30,
            snaplen=HEADERS_SNAPLEN,
            max_size_bytes=50 * 1024 * 1024,
            presigned_url="https://example.com/put",
        )
        assert "CAPTURE_SIZE=" in script
        assert "echo" in script
