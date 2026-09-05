"""Runs a list of events through the rule set and produces alerts (source-agnostic)."""
from typing import Iterable

from siemsim.rules.base import Alert, Event, Rule


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def run(self, events: Iterable[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in sorted(events, key=lambda e: e.timestamp):
            for rule in self.rules:
                alerts.extend(rule.process(event))
        return alerts
