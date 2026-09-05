import unittest
from datetime import datetime

from intel.models import IOC
from intel.storage.ioc_store import init_db, upsert_iocs

from siemsim.parsers.auth_parser import AuthEvent
from siemsim.rules.unknown_ip import UnknownIPRule


def make_event(ip):
    return AuthEvent(timestamp=datetime(2026, 1, 1), ip=ip, user="admin", success=True, raw="raw")


class TestUnknownIPRule(unittest.TestCase):
    def test_alerts_once_for_unknown_ip(self):
        rule = UnknownIPRule(known_ips={"192.168.1.10"})
        first = rule.process(make_event("203.0.113.5"))
        second = rule.process(make_event("203.0.113.5"))
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])

    def test_no_alert_for_known_ip(self):
        rule = UnknownIPRule(known_ips={"192.168.1.10"})
        self.assertEqual(rule.process(make_event("192.168.1.10")), [])

    def test_defaults_to_medium_severity_without_threat_intel(self):
        rule = UnknownIPRule(known_ips={"192.168.1.10"})
        alerts = rule.process(make_event("203.0.113.5"))
        self.assertEqual(alerts[0].severity, "medium")


class TestUnknownIPRuleThreatIntel(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_escalates_to_high_when_ip_is_a_known_bad_ioc(self):
        upsert_iocs(self.conn, [
            IOC(type="ip", value="203.0.113.5", source="urlhaus", threat="malware_download"),
        ])
        rule = UnknownIPRule(known_ips={"192.168.1.10"}, threat_intel_conn=self.conn)

        alerts = rule.process(make_event("203.0.113.5"))

        self.assertEqual(alerts[0].severity, "high")
        self.assertIn("known-bad IOC", alerts[0].message)

    def test_stays_medium_when_ip_is_not_a_known_bad_ioc(self):
        rule = UnknownIPRule(known_ips={"192.168.1.10"}, threat_intel_conn=self.conn)

        alerts = rule.process(make_event("203.0.113.5"))

        self.assertEqual(alerts[0].severity, "medium")

    def test_known_ip_still_produces_no_alert_even_if_also_a_known_bad_ioc(self):
        upsert_iocs(self.conn, [
            IOC(type="ip", value="192.168.1.10", source="urlhaus", threat="malware_download"),
        ])
        rule = UnknownIPRule(known_ips={"192.168.1.10"}, threat_intel_conn=self.conn)

        self.assertEqual(rule.process(make_event("192.168.1.10")), [])


if __name__ == "__main__":
    unittest.main()
