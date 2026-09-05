"""Parses auth.log lines into structured AuthEvent objects."""
import re
from dataclasses import dataclass
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<timestamp>\S+) sshd\[(?P<pid>\d+)\]: "
    r"(?P<verb>Accepted|Failed) password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$"
)


@dataclass
class AuthEvent:
    timestamp: datetime
    ip: str
    user: str
    success: bool
    raw: str


def parse_line(line: str) -> AuthEvent | None:
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    return AuthEvent(
        timestamp=datetime.fromisoformat(match["timestamp"]),
        ip=match["ip"],
        user=match["user"],
        success=match["verb"] == "Accepted",
        raw=line.strip(),
    )


def parse_file(path: str) -> list[AuthEvent]:
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return events
