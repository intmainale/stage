import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(PROJECT_ROOT))

from src.adapters.parsers.apache_parser_adapter import ApacheParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


class TestApacheParserAdapter(unittest.TestCase):

    def setUp(self):
        self.parser = ApacheParserAdapter(path="/tmp/access.log")

    def test_parse_valid_line_returns_apache_event(self):
        raw_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
        event = self.parser.parse(raw_line)

        self.assertIsNotNone(event)
        self.assertEqual(event.ip, "127.0.0.1")
        self.assertEqual(event.user, "frank")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/apache_pb.gif")
        self.assertEqual(event.status, 200)
        self.assertEqual(event.size, 2326)

    def test_parse_empty_line_returns_none(self):
        self.assertIsNone(self.parser.parse(""))

    def test_parse_unmatched_line_returns_none(self):
        self.assertIsNone(self.parser.parse("this is not an apache log line"))

    def test_parse_bad_timestamp_raises_parse_error(self):
        bad_line = '127.0.0.1 - frank [32/Jan/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
        with self.assertRaises(ParseError):
            self.parser.parse(bad_line)

    def test_classify_event_for_high_risk_paths(self):
        self.assertEqual(ApacheParserAdapter.classify_event("/etc/passwd"), "high_risk")
        self.assertEqual(ApacheParserAdapter.classify_event("/bin/sh"), "high_risk")

    def test_classify_event_for_rce_attempts(self):
        self.assertEqual(ApacheParserAdapter.classify_event("/index.php?cmd=ls"), "rce_attempt")
        self.assertEqual(ApacheParserAdapter.classify_event("/shell"), "high_risk")

    def test_classify_event_for_traversal_attempts(self):
        self.assertEqual(ApacheParserAdapter.classify_event("/images/../../index.html"), "traversal_attempt")

    def test_classify_event_for_scanner_activity(self):
        self.assertEqual(ApacheParserAdapter.classify_event("/admin/login"), "scanner_activity")

    def test_classify_event_for_file_upload_attempts(self):
        self.assertEqual(ApacheParserAdapter.classify_event("/upload/file.php"), "file_upload_attempt")

    def test_classify_event_for_normal_paths(self):
        self.assertEqual(ApacheParserAdapter.classify_event("/index.html"), "normal")

    def test_classify_severity_for_known_actions(self):
        self.assertEqual(ApacheParserAdapter.classify_severity("high_risk"), 4)
        self.assertEqual(ApacheParserAdapter.classify_severity("scanner_activity"), 2)

    def test_classify_severity_for_unknown_action(self):
        self.assertEqual(ApacheParserAdapter.classify_severity("unknown_action"), 0)


if __name__ == "__main__":
    unittest.main()
