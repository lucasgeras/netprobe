"""Tests for netprobe. Network-touching probes are exercised against loopback
so the suite stays deterministic and offline-safe."""
from __future__ import annotations

import socket
import threading

import pytest

from netprobe import ProbeResult, dns_probe, tcp_probe, udp_probe


@pytest.fixture
def tcp_server():
    """A throwaway TCP listener on an ephemeral loopback port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield port
    srv.close()


def test_result_str_formatting():
    up = ProbeResult("host", "tcp/22", True, 12.34, "connected")
    assert "UP" in str(up)
    down = ProbeResult("host", "tcp/22", False, None, "refused")
    assert "DOWN" in str(down)


def test_tcp_probe_open_port(tcp_server):
    result = tcp_probe("127.0.0.1", tcp_server, timeout=2.0)
    assert result.ok is True
    assert result.latency_ms is not None
    assert result.protocol == f"tcp/{tcp_server}"


def test_tcp_probe_closed_port():
    # Port 1 is essentially never open on loopback.
    result = tcp_probe("127.0.0.1", 1, timeout=1.0)
    assert result.ok is False
    assert result.latency_ms is None


def test_dns_probe_localhost():
    result = dns_probe("localhost", timeout=2.0)
    assert result.ok is True
    assert "127.0.0.1" in result.detail or "::1" in result.detail


def test_dns_probe_nonexistent():
    result = dns_probe("does-not-exist.invalid", timeout=2.0)
    assert result.ok is False


def test_udp_probe_returns_result():
    result = udp_probe("127.0.0.1", 9, timeout=1.0)
    assert isinstance(result, ProbeResult)
    assert result.protocol == "udp/9"
