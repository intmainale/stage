import pytest

from src.adapters.parsers.bash_parser_adapter import BashParserAdapter
from src.domain.exceptions.domain_exceptions import ParseError


@pytest.fixture
def parser():
    return BashParserAdapter(path="/root/.bash_history")


def test_parse_empty_line_raises_parse_error(parser):
    with pytest.raises(ParseError):
        parser.parse("")


def test_parse_command_returns_bash_event(parser):
    raw_line = "ls -la /tmp"
    event = parser.parse(raw_line)

    assert event.source == "bash"
    assert event.cmd == raw_line
    assert event.action == "command"
    assert event.severity_score == 1


def test_classify_event_download():
    assert BashParserAdapter.classify_event("wget http://example.com/file") == "download"
    assert BashParserAdapter.classify_severity("download") == 4


def test_classify_event_shell():
    assert BashParserAdapter.classify_event("/bin/bash") == "shell"
    assert BashParserAdapter.classify_severity("shell") == 3


def test_classify_event_privilege_escalation():
    assert BashParserAdapter.classify_event("sudo su -") == "privilege_escalation"
    assert BashParserAdapter.classify_severity("privilege_escalation") == 4


def test_classify_event_persistence():
    assert BashParserAdapter.classify_event("crontab -l") == "persistence"
    assert BashParserAdapter.classify_severity("persistence") == 4


def test_classify_event_recon():
    assert BashParserAdapter.classify_event("uname -a") == "recon"
    assert BashParserAdapter.classify_severity("recon") == 2


def test_classify_event_network():
    assert BashParserAdapter.classify_event("nc -lvp 4444") == "network"
    assert BashParserAdapter.classify_severity("network") == 3


def test_classify_event_command_default():
    assert BashParserAdapter.classify_event("echo hello") == "command"
    assert BashParserAdapter.classify_severity("command") == 1