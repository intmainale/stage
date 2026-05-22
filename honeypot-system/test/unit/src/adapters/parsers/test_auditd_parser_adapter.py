import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(PROJECT_ROOT))

from src.adapters.parsers.auditd_parser_adapter import AuditdParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


class TestAuditdParserAdapter(unittest.TestCase):

    def setUp(self):
        self.parser = AuditdParserAdapter(path="/tmp/audit.log")

    def test_parse_empty_line_raises_parse_error(self):
        with self.assertRaises(ParseError):
            self.parser.parse("")

    def test_parse_execve_syscall_returns_event(self):
        raw_line = (
            'type=SYSCALL msg=audit(1716112345.123:456): arch=c000003e syscall=59 success=yes '
            'exe="/usr/bin/curl" comm="curl" pid=1234 uid=1000 ppid=5678'
        )
        event = self.parser.parse(raw_line)

        self.assertIsNotNone(event)
        self.assertEqual(event.source, "auditd")
        self.assertEqual(event.event_id, 456)
        self.assertEqual(event.pid, 1234)
        self.assertEqual(event.ppid, 5678)
        self.assertEqual(event.uid, 1000)
        self.assertEqual(event.exe, "/usr/bin/curl")
        self.assertEqual(event.comm, "curl")
        self.assertTrue(event.success)
        self.assertEqual(event.syscall, "59")
        self.assertEqual(event.raw, raw_line)

    def test_parse_execve_text_syscall_accepts_execve_keyword(self):
        raw_line = (
            'type=SYSCALL msg=audit(1716112345.123:457): arch=c000003e syscall=execve success=yes '
            'exe="/usr/bin/ssh" comm="ssh" pid=2222 uid=1000 ppid=1111'
        )
        event = self.parser.parse(raw_line)

        self.assertIsNotNone(event)
        self.assertEqual(event.syscall, "execve")
        self.assertEqual(event.event_id, 457)

    def test_parse_non_execve_syscall_returns_none(self):
        raw_line = (
            'type=SYSCALL msg=audit(1716112345.123:458): arch=c000003e syscall=2 success=no '
            'exe="/usr/bin/ls" comm="ls" pid=3333 uid=1000 ppid=1111'
        )
        self.assertIsNone(self.parser.parse(raw_line))

    def test_parse_line_without_audit_message_returns_event_with_missing_ts_and_id(self):
        raw_line = (
            'type=SYSCALL arch=c000003e syscall=59 success=yes '
            'exe="/usr/bin/curl" comm="curl" pid=1234 uid=1000 ppid=5678'
        )
        event = self.parser.parse(raw_line)

        self.assertIsNotNone(event)
        self.assertIsNone(event.timestamp)
        self.assertIsNone(event.event_id)
        self.assertEqual(event.syscall, "59")


if __name__ == "__main__":
    unittest.main()
