import argparse
import os
import unittest
from unittest.mock import MagicMock, patch

import main as cli


class TestCmdDetectThreatIntelGating(unittest.TestCase):
    @patch("main.init_threat_intel_db")
    @patch("main.parse_firewall_file", return_value=[])
    def test_does_not_open_threat_intel_conn_when_env_var_unset(self, mock_parse, mock_init_db):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("THREAT_INTEL_DB", None)
            args = argparse.Namespace(type="firewall", file="unused.log")
            cli.cmd_detect(args)

        mock_init_db.assert_not_called()

    @patch("main.init_threat_intel_db")
    @patch("main.parse_firewall_file", return_value=[])
    def test_opens_and_closes_threat_intel_conn_when_env_var_set(self, mock_parse, mock_init_db):
        mock_conn = MagicMock()
        mock_init_db.return_value = mock_conn

        with patch.dict(os.environ, {"THREAT_INTEL_DB": "/tmp/whatever.db"}):
            args = argparse.Namespace(type="firewall", file="unused.log")
            cli.cmd_detect(args)

        mock_init_db.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("main.init_threat_intel_db")
    @patch("main.parse_firewall_file", return_value=[])
    def test_does_not_open_threat_intel_conn_when_env_var_is_empty_string(self, mock_parse, mock_init_db):
        with patch.dict(os.environ, {"THREAT_INTEL_DB": ""}):
            args = argparse.Namespace(type="firewall", file="unused.log")
            cli.cmd_detect(args)

        mock_init_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
