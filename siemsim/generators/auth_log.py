"""Generates fake SSH auth.log lines (normal traffic + brute-force bursts)."""
import random
from datetime import datetime, timedelta
from pathlib import Path

KNOWN_USERS = ["berkin", "deploy"]
UNKNOWN_USERS = ["admin", "root", "test", "guest", "oracle", "ubuntu"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"]
SUSPICIOUS_IPS = ["203.0.113.5", "198.51.100.23", "45.155.205.7"]


def _format_line(ts: datetime, pid: int, success: bool, user: str, ip: str, port: int) -> str:
    verb = "Accepted" if success else "Failed"
    prefix = "" if user in KNOWN_USERS else "invalid user "
    return f"{ts.isoformat()} sshd[{pid}]: {verb} password for {prefix}{user} from {ip} port {port} ssh2"


def generate_auth_log(
    num_lines: int = 200,
    brute_force_bursts: int = 2,
    out_path: str = "logs/auth.log",
    seed: int | None = None,
) -> str:
    if seed is not None:
        random.seed(seed)
        # Anchor to a fixed reference time when seeded so the output is byte-for-byte
        # reproducible across runs; wall-clock time would otherwise differ.
        reference_now = datetime(2024, 1, 1)
    else:
        reference_now = datetime.now()

    start = reference_now - timedelta(seconds=num_lines * 7)
    events: list[tuple[datetime, str, str, bool]] = []

    for i in range(num_lines):
        ts = start + timedelta(seconds=i * 7)
        ip = random.choice(NORMAL_IPS)
        user = random.choice(KNOWN_USERS)
        success = random.random() < 0.9
        events.append((ts, ip, user, success))

    for _ in range(brute_force_bursts):
        ip = random.choice(SUSPICIOUS_IPS)
        burst_start = start + timedelta(seconds=random.randint(0, num_lines * 7))
        for j in range(random.randint(8, 15)):
            ts = burst_start + timedelta(seconds=j * 2)
            user = random.choice(UNKNOWN_USERS)
            events.append((ts, ip, user, False))

    events.sort(key=lambda e: e[0])

    lines = []
    pid = 10000
    for ts, ip, user, success in events:
        pid += 1
        lines.append(_format_line(ts, pid, success, user, ip, random.randint(30000, 60000)))

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines) + "\n")
    return str(out_file)
