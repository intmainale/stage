import pytest

from src.adapters.parsers.auditd_parser_adapter import AuditdParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


@pytest.fixture
def parser():
    return AuditdParserAdapter(path="/tmp/audit.log")


def test_parse_empty_line_raises_parse_error(parser):
    with pytest.raises(ParseError):
        parser.parse("")


def test_parse_execve_syscall_returns_event(parser):
    raw_line = (
        'type=SYSCALL msg=audit(1716112345.123:456): arch=c000003e syscall=59 success=yes '
        'exe="/usr/bin/curl" comm="curl" pid=1234 uid=1000 ppid=5678'
    )
    event = parser.parse(raw_line)

    assert event is not None
    assert event.source == "auditd"
    assert event.event_id == 456
    assert event.pid == 1234
    assert event.ppid == 5678
    assert event.uid == 1000
    assert event.exe == "/usr/bin/curl"
    assert event.comm == "curl"
    assert event.success
    assert event.syscall == "59"
    assert event.raw == raw_line


def test_parse_execve_text_syscall_accepts_execve_keyword(parser):
    raw_line = (
        'type=SYSCALL msg=audit(1716112345.123:457): arch=c000003e syscall=execve success=yes '
        'exe="/usr/bin/ssh" comm="ssh" pid=2222 uid=1000 ppid=1111'
    )
    event = parser.parse(raw_line)

    assert event is not None
    assert event.syscall == "execve"
    assert event.event_id == 457


def test_parse_non_execve_syscall_returns_none(parser):
    raw_line = (
        'type=SYSCALL msg=audit(1716112345.123:458): arch=c000003e syscall=2 success=no '
        'exe="/usr/bin/ls" comm="ls" pid=3333 uid=1000 ppid=1111'
    )
    assert parser.parse(raw_line) is None


def test_parse_line_without_audit_message_returns_event_with_missing_ts_and_id(parser):
    raw_line = (
        'type=SYSCALL arch=c000003e syscall=59 success=yes '
        'exe="/usr/bin/curl" comm="curl" pid=1234 uid=1000 ppid=5678'
    )
    event = parser.parse(raw_line)

    assert event is not None
    assert event.timestamp is None
    assert event.event_id is None
    assert event.syscall == "59"