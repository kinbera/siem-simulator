import unittest
from datetime import datetime, timedelta

from siemsim.parsers.auth_parser import AuthEvent
from siemsim.rules.repeated_failed_login import RepeatedFailedLoginRule


def make_event(seconds_offset, ip="203.0.113.5", success=False):
    return AuthEvent(
        timestamp=datetime(2026, 1, 1) + timedelta(seconds=seconds_offset),
        ip=ip,
        user="admin",
        success=success,
        raw="raw",
    )


class TestRepeatedFailedLoginRule(unittest.TestCase):
    def test_triggers_after_threshold_within_window(self):
        rule = RepeatedFailedLoginRule(threshold=3, window=timedelta(minutes=1))
        alerts = []
        for i in range(3):
            alerts.extend(rule.process(make_event(i * 5)))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, "repeated_failed_login")

    def test_does_not_trigger_below_threshold(self):
        rule = RepeatedFailedLoginRule(threshold=5, window=timedelta(minutes=1))
        alerts = []
        for i in range(3):
            alerts.extend(rule.process(make_event(i * 5)))
        self.assertEqual(alerts, [])

    def test_does_not_trigger_outside_window(self):
        rule = RepeatedFailedLoginRule(threshold=3, window=timedelta(seconds=30))
        alerts = []
        for i in range(3):
            alerts.extend(rule.process(make_event(i * 60)))
        self.assertEqual(alerts, [])

    def test_successful_login_resets_counter(self):
        rule = RepeatedFailedLoginRule(threshold=3, window=timedelta(minutes=1))
        rule.process(make_event(0))
        rule.process(make_event(5))
        rule.process(make_event(10, success=True))
        alerts = rule.process(make_event(15))
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
