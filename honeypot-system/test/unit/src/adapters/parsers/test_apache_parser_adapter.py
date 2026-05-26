import pytest

from src.adapters.parsers.apache_parser_adapter import ApacheParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


@pytest.fixture
def parser():
    return ApacheParserAdapter(path="/tmp/access.log")


def test_parse_valid_line_returns_apache_event(parser):
    raw_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
    event = parser.parse(raw_line)

    assert event is not None
    assert event.ip == "127.0.0.1"
    assert event.user == "frank"
    assert event.method == "GET"
    assert event.path == "/apache_pb.gif"
    assert event.status == 200
    assert event.size == 2326


def test_parse_empty_line_returns_none(parser):
    assert parser.parse("") is None


def test_parse_unmatched_line_returns_none(parser):
    assert parser.parse("this is not an apache log line") is None


def test_parse_bad_timestamp_raises_parse_error(parser):
    bad_line = '127.0.0.1 - frank [32/Jan/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
    with pytest.raises(ParseError):
        parser.parse(bad_line)


def test_classify_event_for_high_risk_paths():
    assert ApacheParserAdapter.classify_event("/etc/passwd") == "high_risk"
    assert ApacheParserAdapter.classify_event("/bin/sh") == "high_risk"


def test_classify_event_for_rce_attempts():
    assert ApacheParserAdapter.classify_event("/index.php?cmd=ls") == "rce_attempt"
    assert ApacheParserAdapter.classify_event("/shell") == "high_risk"


def test_classify_event_for_traversal_attempts():
    assert ApacheParserAdapter.classify_event("/images/../../index.html") == "traversal_attempt"


def test_classify_event_for_scanner_activity():
    assert ApacheParserAdapter.classify_event("/admin/login") == "scanner_activity"


def test_classify_event_for_file_upload_attempts():
    assert ApacheParserAdapter.classify_event("/upload/file.php") == "file_upload_attempt"


def test_classify_event_for_normal_paths():
    assert ApacheParserAdapter.classify_event("/index.html") == "normal"


def test_classify_severity_for_known_actions():
    assert ApacheParserAdapter.classify_severity("high_risk") == 4
    assert ApacheParserAdapter.classify_severity("scanner_activity") == 2


def test_classify_severity_for_unknown_action():
    assert ApacheParserAdapter.classify_severity("unknown_action") == 0