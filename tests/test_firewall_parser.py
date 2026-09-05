import unittest

from siemsim.parsers.firewall_parser import parse_line


class TestFirewallParser(unittest.TestCase):
    def test_parse_allow_line(self):
        line = "2026-01-01T00:00:00 firewall action=ALLOW src=192.168.1.10 dst=10.0.0.1 dport=443 proto=TCP"
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.action, "ALLOW")
        self.assertEqual(event.ip, "192.168.1.10")
        self.assertEqual(event.dst_port, 443)

    def test_parse_unrelated_line_returns_none(self):
        self.assertIsNone(parse_line("not a firewall line"))


if __name__ == "__main__":
    unittest.main()
