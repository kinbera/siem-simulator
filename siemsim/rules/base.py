"""Common interface all detection rules must implement."""
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Event(Protocol):
    """Minimum fields an event must expose for a rule to process it."""
    timestamp: datetime
    ip: str
    raw: str


@dataclass
class Alert:
    rule: str
    severity: str
    message: str
    event: Any


class Rule:
    name = "base"

    def process(self, event: Event) -> list[Alert]:
        """Processes a single event, returns a list of alerts if triggered."""
        raise NotImplementedError
