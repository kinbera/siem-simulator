"""Flags activity from an IP outside the known/allowed list (once per IP).

Severity escalates to "high" when the IP also matches a known-bad IOC in the
threat-intel-aggregator local store (see README: Threat intel enrichment).
"""
import sqlite3

from intel.lookup.checker import check_ip as check_known_bad_ip

from siemsim.rules.base import Alert, Event, Rule


class UnknownIPRule(Rule):
    name = "unknown_ip"

    def __init__(self, known_ips: set[str], threat_intel_conn: sqlite3.Connection | None = None):
        self.known_ips = known_ips
        self.threat_intel_conn = threat_intel_conn
        self._alerted_ips: set[str] = set()

    def process(self, event: Event) -> list[Alert]:
        if event.ip in self.known_ips or event.ip in self._alerted_ips:
            return []

        self._alerted_ips.add(event.ip)

        severity = "medium"
        message = f"Activity from unknown/unexpected IP address: {event.ip}"
        if self.threat_intel_conn is not None and check_known_bad_ip(self.threat_intel_conn, event.ip):
            severity = "high"
            message = f"Activity from unknown IP address that is also a known-bad IOC: {event.ip}"

        return [Alert(rule=self.name, severity=severity, message=message, event=event)]
