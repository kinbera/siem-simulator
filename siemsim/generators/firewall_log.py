"""Generates fake firewall log lines (normal traffic + activity from unknown IPs)."""
import random
from datetime import datetime, timedelta
from pathlib import Path

KNOWN_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"]
UNKNOWN_IPS = ["203.0.113.5", "198.51.100.23", "45.155.205.7", "185.220.101.9"]
INTERNAL_DST = "10.0.0.1"
COMMON_PORTS = [80, 443]
SENSITIVE_PORTS = [22, 3389, 3306, 5432]


def _format_line(ts: datetime, action: str, src_ip: str, dst_port: int, proto: str) -> str:
    return (
        f"{ts.isoformat()} firewall action={action} src={src_ip} "
        f"dst={INTERNAL_DST} dport={dst_port} proto={proto}"
    )


def generate_firewall_log(
    num_lines: int = 200,
    unknown_ip_events: int = 4,
    out_path: str = "logs/firewall.log",
    seed: int | None = None,
) -> str:
    if seed is not None:
        random.seed(seed)
        # Anchor to a fixed reference time when seeded so the output is byte-for-byte
        # reproducible across runs; wall-clock time would otherwise differ.
        reference_now = datetime(2024, 1, 1)
    else:
        reference_now = datetime.now()

    start = reference_now - timedelta(seconds=num_lines * 5)
    events: list[tuple[datetime, str, str, int, str]] = []

    for i in range(num_lines):
        ts = start + timedelta(seconds=i * 5)
        ip = random.choice(KNOWN_IPS)
        port = random.choice(COMMON_PORTS)
        events.append((ts, "ALLOW", ip, port, "TCP"))

    for _ in range(unknown_ip_events):
        ip = random.choice(UNKNOWN_IPS)
        ts = start + timedelta(seconds=random.randint(0, num_lines * 5))
        port = random.choice(SENSITIVE_PORTS)
        action = random.choice(["DENY", "DENY", "ALLOW"])
        events.append((ts, action, ip, port, "TCP"))

    events.sort(key=lambda e: e[0])

    lines = [_format_line(ts, action, ip, port, proto) for ts, action, ip, port, proto in events]

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines) + "\n")
    return str(out_file)
