# netprobe

Lightweight, dependency-free host **connectivity testing** across the protocols
you reach for when a Linux host "isn't responding": ICMP, TCP, UDP, DNS, SSH and
HTTP(S). Use it as a library or from the command line.

## Why

`ping` tells you one thing. When you actually need to know *how* a host is
reachable — is DNS resolving? is 443 open? does SSH answer? — you end up
stringing together `ping`, `nc`, `dig`, `curl` and `ssh -v`. `netprobe` wraps
those checks behind one consistent, scriptable interface that returns structured
results and a meaningful exit code.

## Install

```bash
pip install -e .
```

No third-party runtime dependencies — everything rides on the Python standard
library (ICMP shells out to the system `ping`).

## CLI

```bash
netprobe example.com                     # default: ICMP + DNS
netprobe example.com --tcp 22,80,443     # TCP handshake to several ports
netprobe example.com --ssh --http        # SSH banner + HTTP status
netprobe 10.0.0.5 --udp 53 --timeout 1.5
```

Sample output:

```
[UP  ] icmp       example.com                     14.2 ms  echo reply
[UP  ] dns        example.com                      2.1 ms  93.184.216.34
[UP  ] tcp/443    example.com                     18.9 ms  connected
[DOWN] tcp/22     example.com                        -     [Errno 111] Connection refused
```

Exit code is `0` only if every probe came back `UP`, so it drops straight into
CI or a health-check script.

## Library

```python
from netprobe import tcp_probe, ssh_probe, dns_probe

r = tcp_probe("10.0.0.5", 5432, timeout=2.0)
if r.ok:
    print(f"Postgres port reachable in {r.latency_ms:.1f} ms")

for r in (dns_probe("db.internal"), ssh_probe("db.internal")):
    print(r)
```

Every probe returns a `ProbeResult(host, protocol, ok, latency_ms, detail)`.

## Supported probes

| Function       | Protocol | Notes                                             |
|----------------|----------|---------------------------------------------------|
| `ping_probe`   | ICMP     | Uses the system `ping` (no raw-socket root needed) |
| `tcp_probe`    | TCP      | Full connect handshake to a port                   |
| `udp_probe`    | UDP      | Best-effort; reports `open|filtered` on silence    |
| `dns_probe`    | DNS      | Resolves and returns all A/AAAA records            |
| `ssh_probe`    | SSH      | Connects and validates the `SSH-` banner           |
| `http_probe`   | HTTP(S)  | Returns the response status line                   |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
