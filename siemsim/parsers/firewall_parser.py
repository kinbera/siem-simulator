"""Parses firewall.log lines into structured FirewallEvent objects."""
import re
from dataclasses import dataclass
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<timestamp>\S+) firewall action=(?P<action>ALLOW|DENY) "
    r"src=(?P<ip>\S+) dst=(?P<dst>\S+) dport=(?P<dport>\d+) proto=(?P<proto>\S+)$"
)


@dataclass
class FirewallEvent:
    timestamp: datetime
    ip: str
    dst: str
    dst_port: int
    proto: str
    action: str
    raw: str


def parse_line(line: str) -> FirewallEvent | None:
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    return FirewallEvent(
        timestamp=datetime.fromisoformat(match["timestamp"]),
        ip=match["ip"],
        dst=match["dst"],
        dst_port=int(match["dport"]),
        proto=match["proto"],
        action=match["action"],
        raw=line.strip(),
    )


def parse_file(path: str) -> list[FirewallEvent]:
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return events
