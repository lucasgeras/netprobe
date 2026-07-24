"""Connectivity probes for a handful of common host-reachability protocols.

Each probe returns a :class:`ProbeResult` describing whether the target was
reachable, how long it took, and any protocol-specific detail (a banner, an
HTTP status, a resolved address, ...).

The probes intentionally lean on the standard library so the package is
dependency-free and runnable anywhere Python 3.8+ is installed. ICMP is done by
shelling out to the system ``ping`` binary, which avoids the raw-socket root
requirement.
"""
from __future__ import annotations

import platform
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

DEFAULT_TIMEOUT = 3.0


@dataclass
class ProbeResult:
    """Outcome of a single connectivity probe."""

    host: str
    protocol: str
    ok: bool
    latency_ms: Optional[float] = None
    detail: str = ""

    def __str__(self) -> str:
        status = "UP  " if self.ok else "DOWN"
        latency = f"{self.latency_ms:7.1f} ms" if self.latency_ms is not None else "        -  "
        return f"[{status}] {self.protocol:<10} {self.host:<28} {latency}  {self.detail}"


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def tcp_probe(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Attempt a TCP handshake to ``host:port``."""
    proto = f"tcp/{port}"
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ProbeResult(host, proto, True, _elapsed_ms(start), "connected")
    except OSError as exc:
        return ProbeResult(host, proto, False, None, str(exc))


def udp_probe(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Best-effort UDP reachability check.

    UDP is connectionless, so "reachable" is fuzzy: we send an empty datagram
    and treat an explicit ICMP port-unreachable (``ECONNREFUSED``) as *down*.
    Silence is reported as *open|filtered*, matching how ``nmap`` describes it.
    """
    proto = f"udp/{port}"
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"", (host, port))
        try:
            sock.recvfrom(1024)
            return ProbeResult(host, proto, True, _elapsed_ms(start), "response received")
        except socket.timeout:
            return ProbeResult(host, proto, True, None, "open|filtered (no reply)")
    except OSError as exc:
        return ProbeResult(host, proto, False, None, str(exc))
    finally:
        sock.close()


def ping_probe(host: str, count: int = 1, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """ICMP echo via the system ``ping`` binary (cross-platform flag handling)."""
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    # Windows -w expects milliseconds; Unix -W expects seconds.
    timeout_flag = "-w" if is_windows else "-W"
    timeout_val = str(int(timeout * 1000)) if is_windows else str(int(timeout))
    cmd = ["ping", count_flag, str(count), timeout_flag, timeout_val, host]

    start = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout * count + 2,
            text=True,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return ProbeResult(host, "icmp", False, None, str(exc))

    if completed.returncode == 0:
        match = re.search(r"time[=<]\s*([\d.]+)\s*ms", completed.stdout)
        latency = float(match.group(1)) if match else _elapsed_ms(start)
        return ProbeResult(host, "icmp", True, latency, "echo reply")
    return ProbeResult(host, "icmp", False, None, "no echo reply")


def dns_probe(host: str, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Resolve ``host`` to an address (checks DNS reachability + resolution)."""
    start = time.perf_counter()
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({info[4][0] for info in infos})
        return ProbeResult(host, "dns", True, _elapsed_ms(start), ", ".join(addrs))
    except socket.gaierror as exc:
        return ProbeResult(host, "dns", False, None, str(exc))
    finally:
        socket.setdefaulttimeout(original)


def ssh_probe(host: str, port: int = 22, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Connect to an SSH port and read the server identification banner."""
    proto = f"ssh/{port}"
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode("utf-8", "replace").strip()
        detail = banner if banner.startswith("SSH-") else f"unexpected banner: {banner!r}"
        return ProbeResult(host, proto, banner.startswith("SSH-"), _elapsed_ms(start), detail)
    except OSError as exc:
        return ProbeResult(host, proto, False, None, str(exc))


def http_probe(url: str, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """HTTP(S) HEAD/GET reachability check returning the status line."""
    if "://" not in url:
        url = "http://" + url
    proto = "https" if url.startswith("https") else "http"
    host = urllib.request.urlparse(url).hostname or url
    start = time.perf_counter()
    context = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "netprobe"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return ProbeResult(host, proto, True, _elapsed_ms(start), f"HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        # Reachable, just a non-2xx/3xx response.
        return ProbeResult(host, proto, True, _elapsed_ms(start), f"HTTP {exc.code}")
    except (urllib.error.URLError, OSError) as exc:
        return ProbeResult(host, proto, False, None, str(exc))
