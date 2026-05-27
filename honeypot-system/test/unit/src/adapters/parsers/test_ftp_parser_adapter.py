import pytest

from src.adapters.parsers.ftp_parser_adapter import FTPParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


@pytest.fixture
def parser():
    return FTPParserAdapter(path="/var/log/proftpd/extended.log")


def test_parse_xferlog_upload_returns_ftp_event(parser):
    raw_line = (
        "Tue May 26 16:20:01 2026 2 198.51.100.10 4096 "
        "/incoming/shell.php b _ i a anonymous ftp 0 * c"
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-xferlog"
    assert event.ip == "198.51.100.10"
    assert event.username == "anonymous"
    assert event.operation == "upload"
    assert event.action == "suspicious_path"
    assert event.success is True
    assert event.bytes_transferred == 4096
    assert event.severity_score == 4
    assert "log_format" not in event.to_dict()
    assert "transfer_seconds" not in event.to_dict()
    assert "transfer_type" not in event.to_dict()
    assert "direction" not in event.to_dict()


def test_parse_xferlog_hostname_extracts_ip(parser):
    raw_line = (
        "Wed May 27 12:43:39 2026 0 "
        "host-62-110-23-211.business.telecomitalia.it 0 "
        "/home/user/test.txt b _ o r user ftp 0 * c"
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-xferlog"
    assert event.ip == "62.110.23.211"
    assert event.username == "user"
    assert event.operation == "download"
    assert event.action == "file_download"
    assert event.file_path == "/home/user/test.txt"


def test_parse_extended_user_command_returns_ftp_event(parser):
    raw_line = (
        'host-62-110-23-211.business.telecomitalia.it UNKNOWN - '
        '[27/May/2026:12:42:29 +0000] "USER user" 331 -'
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.ip == "62.110.23.211"
    assert event.username is None
    assert event.command == "USER"
    assert event.operation == "login"
    assert event.action == "login"
    assert event.success is True
    assert event.status == "331"
    assert event.file_path is None


def test_parse_extended_stor_failure_returns_ftp_event(parser):
    raw_line = (
        'host-62-110-23-211.business.telecomitalia.it UNKNOWN user '
        '[27/May/2026:12:42:29 +0000] "STOR test.txt" 550 -'
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.ip == "62.110.23.211"
    assert event.username == "user"
    assert event.command == "STOR"
    assert event.operation == "upload"
    assert event.file_path == "test.txt"
    assert event.status == "550"
    assert event.success is False
    assert event.action == "file_upload"


def test_parse_access_extended_hostname_extracts_ip(parser):
    raw_line = (
        'host-62-110-23-211.business.telecomitalia.it UNKNOWN user '
        '[27/May/2026:12:27:10 +0000] "MFMT 20260526140946 test.txt" 213 -'
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.ip == "62.110.23.211"
    assert event.username == "user"
    assert event.command == "MFMT"
    assert event.operation == "command"
    assert event.file_path == "test.txt"
    assert event.status == "213"
    assert event.success is True
    assert event.bytes_transferred is None


def test_parse_extended_retr_success_returns_bytes(parser):
    raw_line = (
        'host-62-110-23-211.business.telecomitalia.it UNKNOWN user '
        '[27/May/2026:12:43:39 +0000] "RETR test.txt" 226 0'
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.ip == "62.110.23.211"
    assert event.command == "RETR"
    assert event.operation == "download"
    assert event.action == "file_download"
    assert event.file_path == "test.txt"
    assert event.success is True
    assert event.bytes_transferred == 0


def test_parse_extended_dash_status_returns_unknown_success(parser):
    raw_line = (
        'host-62-110-23-211.business.telecomitalia.it UNKNOWN - '
        '[27/May/2026:12:42:29 +0000] "OPTS UTF8 ON" - -'
    )

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.command == "OPTS"
    assert event.operation == "session"
    assert event.status is None
    assert event.success is None
    assert event.file_path is None


def test_parse_unrecognized_line_returns_none(parser):
    assert parser.parse("this is not an ftp log") is None


def test_parse_bad_extended_timestamp_raises_parse_error(parser):
    raw_line = (
        'host-62-110-23-211.business.telecomitalia.it UNKNOWN user '
        '[99/Foo/2026:12:42:29 +0000] "STOR test.txt" 550 -'
    )

    with pytest.raises(ParseError):
        parser.parse(raw_line)
