import unittest

from siemsim.parsers.auth_parser import parse_line


class TestAuthParser(unittest.TestCase):
    def test_parse_accepted_line(self):
        line = "2026-01-01T00:00:00 sshd[123]: Accepted password for deploy from 10.0.0.5 port 40000 ssh2"
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertTrue(event.success)
        self.assertEqual(event.user, "deploy")
        self.assertEqual(event.ip, "10.0.0.5")

    def test_parse_failed_invalid_user_line(self):
        line = "2026-01-01T00:00:00 sshd[124]: Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2"
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertFalse(event.success)
        self.assertEqual(event.user, "admin")

    def test_parse_unrelated_line_returns_none(self):
        self.assertIsNone(parse_line("some unrelated log line"))


if __name__ == "__main__":
    unittest.main()
