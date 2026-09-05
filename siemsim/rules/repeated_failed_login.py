"""Detects repeated failed login attempts from the same IP within a short window (brute-force indicator)."""
from collections import deque
from datetime import timedelta

from siemsim.parsers.auth_parser import AuthEvent
from siemsim.rules.base import Alert, Rule


class RepeatedFailedLoginRule(Rule):
    name = "repeated_failed_login"

    def __init__(self, threshold: int = 5, window: timedelta = timedelta(minutes=2)):
        self.threshold = threshold
        self.window = window
        self._failures_by_ip: dict[str, deque[AuthEvent]] = {}
        self._alerted_ips: set[str] = set()

    def process(self, event: AuthEvent) -> list[Alert]:
        if event.success:
            self._failures_by_ip.pop(event.ip, None)
            self._alerted_ips.discard(event.ip)
            return []

        bucket = self._failures_by_ip.setdefault(event.ip, deque())
        bucket.append(event)
        while bucket and event.timestamp - bucket[0].timestamp > self.window:
            bucket.popleft()

        if len(bucket) >= self.threshold and event.ip not in self._alerted_ips:
            self._alerted_ips.add(event.ip)
            return [Alert(
                rule=self.name,
                severity="high",
                message=(
                    f"{event.ip}: {len(bucket)} failed login attempts within "
                    f"{int(self.window.total_seconds() // 60)} minutes (possible brute force)"
                ),
                event=event,
            )]
        return []
