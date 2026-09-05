import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime

from siemsim.dashboard.cli_dashboard import render
from siemsim.rules.base import Alert


class TestDashboard(unittest.TestCase):
    def test_render_with_no_alerts(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            render([], title="test")
        self.assertIn("No suspicious activity found.", buf.getvalue())

    def test_render_with_alerts_includes_summary_and_details(self):
        alert = Alert(
            rule="unknown_ip",
            severity="medium",
            message="Activity from unknown/unexpected IP address: 203.0.113.5",
            event=type("E", (), {"timestamp": datetime(2026, 1, 1, 12, 0, 0)})(),
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            render([alert], title="test")
        output = buf.getvalue()
        self.assertIn("Total alerts: 1", output)
        self.assertIn("unknown_ip", output)
        self.assertIn("203.0.113.5", output)


if __name__ == "__main__":
    unittest.main()
