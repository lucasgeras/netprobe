"""Command-line front-end for netprobe.

Examples
--------
    netprobe example.com                 # icmp + dns by default
    netprobe example.com --tcp 22,80,443
    netprobe example.com --ssh --http
    netprobe 10.0.0.5 --tcp 3306 --udp 53 --timeout 1.5
"""
from __future__ import annotations

import argparse
import sys
from typing import List

from . import __version__
from .probes import (
    ProbeResult,
    dns_probe,
    http_probe,
    ping_probe,
    ssh_probe,
    tcp_probe,
    udp_probe,
)


def _ports(raw: str) -> List[int]:
    return [int(p.strip()) for p in raw.split(",") if p.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Test host reachability across ICMP, TCP, UDP, DNS, SSH and HTTP.",
    )
    parser.add_argument("host", help="target hostname or IP address")
    parser.add_argument("--icmp", action="store_true", help="ICMP echo (ping)")
    parser.add_argument("--dns", action="store_true", help="DNS resolution")
    parser.add_argument("--tcp", metavar="PORTS", help="comma-separated TCP ports")
    parser.add_argument("--udp", metavar="PORTS", help="comma-separated UDP ports")
    parser.add_argument("--ssh", action="store_true", help="SSH banner grab on port 22")
    parser.add_argument("--http", action="store_true", help="HTTP(S) request")
    parser.add_argument("--timeout", type=float, default=3.0, help="per-probe timeout (s)")
    parser.add_argument("--version", action="version", version=f"netprobe {__version__}")
    return parser


def run(host: str, args: argparse.Namespace) -> List[ProbeResult]:
    results: List[ProbeResult] = []
    # If no protocol was selected, fall back to a sensible default set.
    selected_any = any([args.icmp, args.dns, args.tcp, args.udp, args.ssh, args.http])

    if args.icmp or not selected_any:
        results.append(ping_probe(host, timeout=args.timeout))
    if args.dns or not selected_any:
        results.append(dns_probe(host, timeout=args.timeout))
    if args.tcp:
        results.extend(tcp_probe(host, port, args.timeout) for port in _ports(args.tcp))
    if args.udp:
        results.extend(udp_probe(host, port, args.timeout) for port in _ports(args.udp))
    if args.ssh:
        results.append(ssh_probe(host, timeout=args.timeout))
    if args.http:
        results.append(http_probe(host, timeout=args.timeout))
    return results


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results = run(args.host, args)
    for result in results:
        print(result)
    # Exit non-zero if anything was unreachable -- handy in CI / scripts.
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
