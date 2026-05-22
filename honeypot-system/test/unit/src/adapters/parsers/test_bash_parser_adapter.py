import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(PROJECT_ROOT))

from src.adapters.parsers.bash_parser_adapter import BashParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


class TestBashParserAdapter(unittest.TestCase):

    def setUp(self):
        self.parser = BashParserAdapter(path="/tmp/.bash_history")

    def test_parse_empty_line_raises_parse_error(self):
        with self.assertRaises(ParseError):
            self.parser.parse("")

    def test_parse_command_returns_bash_event(self):
        raw_line = "ls -la /tmp"
        event = self.parser.parse(raw_line)

        self.assertEqual(event.source, "bash")
        self.assertEqual(event.cmd, raw_line)
        self.assertEqual(event.action, "command")
        self.assertEqual(event.severity_score, 1)

    def test_classify_event_download(self):
        self.assertEqual(BashParserAdapter.classify_event("wget http://example.com/file"), "download")
        self.assertEqual(BashParserAdapter.classify_severity("download"), 4)

    def test_classify_event_shell(self):
        self.assertEqual(BashParserAdapter.classify_event("/bin/bash"), "shell")
        self.assertEqual(BashParserAdapter.classify_severity("shell"), 3)

    def test_classify_event_privilege_escalation(self):
        self.assertEqual(BashParserAdapter.classify_event("sudo su -"), "privilege_escalation")
        self.assertEqual(BashParserAdapter.classify_severity("privilege_escalation"), 4)

    def test_classify_event_persistence(self):
        self.assertEqual(BashParserAdapter.classify_event("crontab -l"), "persistence")
        self.assertEqual(BashParserAdapter.classify_severity("persistence"), 4)

    def test_classify_event_recon(self):
        self.assertEqual(BashParserAdapter.classify_event("uname -a"), "recon")
        self.assertEqual(BashParserAdapter.classify_severity("recon"), 2)

    def test_classify_event_network(self):
        self.assertEqual(BashParserAdapter.classify_event("nc -lvp 4444"), "network")
        self.assertEqual(BashParserAdapter.classify_severity("network"), 3)

    def test_classify_event_command_default(self):
        self.assertEqual(BashParserAdapter.classify_event("echo hello"), "command")
        self.assertEqual(BashParserAdapter.classify_severity("command"), 1)


if __name__ == "__main__":
    unittest.main()
