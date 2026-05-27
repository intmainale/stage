import pytest

from src.adapters.parsers.ftp_parser_adapter import FTPParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


@pytest.fixture
def parser():
    return FTPParserAdapter(path="/var/log/vsftpd.log")


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


def test_parse_extended_failed_login_returns_ftp_event(parser):
    raw_line = 'Tue May 26 16:21:02 2026 [pid 1234] [admin] FAIL LOGIN: Client "203.0.113.7"'

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.ip == "203.0.113.7"
    assert event.username == "admin"
    assert event.operation == "login"
    assert event.action == "failed_login"
    assert event.success is False
    assert event.pid == 1234
    assert event.severity_score == 2


def test_parse_extended_ftp_command_returns_ftp_event(parser):
    raw_line = 'Tue May 26 16:22:03 2026 [pid 1235] [ftp] FTP command: Client "203.0.113.8", "RETR /pub/readme.txt"'

    event = parser.parse(raw_line)

    assert event.source == "ftp-extended"
    assert event.ip == "203.0.113.8"
    assert event.username == "ftp"
    assert event.command == "RETR"
    assert event.operation == "download"
    assert event.file_path == "/pub/readme.txt"
    assert event.action == "file_download"


def test_parse_unrecognized_line_returns_none(parser):
    assert parser.parse("this is not an ftp log") is None


def test_parse_bad_extended_timestamp_raises_parse_error(parser):
    raw_line = 'Tue Foo 99 16:21:02 2026 [pid 1234] [admin] FAIL LOGIN: Client "203.0.113.7"'

    with pytest.raises(ParseError):
        parser.parse(raw_line)
