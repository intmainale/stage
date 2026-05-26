import json

import pytest

from src.adapters.publishers import debug_publisher_adapter as debug_module
from src.adapters.publishers.debug_publisher_adapter import DebugFilePublisherAdapter
from src.domain.exceptions.domain_exceptions import PublishError
from src.domain.models.event import BashEvent


class DummySettings:
    def __init__(self, output_path: str):
        self._output_path = output_path

    def get(self, key: str, default=None):
        if key == "debug.output_path":
            return self._output_path
        return default


def test_debug_file_publisher_writes_json(tmp_path, monkeypatch):
    output_file = tmp_path / "debug_events.log"
    monkeypatch.setattr("config.settings.Settings.get_instance", lambda: DummySettings(str(output_file)))

    publisher = DebugFilePublisherAdapter()
    event = BashEvent(source="test-source", cmd="echo hello", action="command", severity_score=1)
    publisher.publish(event)
    publisher.close()

    contents = output_file.read_text(encoding="utf-8")
    parsed = json.loads(contents.strip())

    assert parsed["cmd"] == "echo hello"
    assert parsed["action"] == "command"
    assert parsed["severity_score"] == 1


def test_debug_file_publisher_raises_when_directory_cannot_be_created(tmp_path, monkeypatch):
    output_file = tmp_path / "debug_events.log"
    monkeypatch.setattr("config.settings.Settings.get_instance", lambda: DummySettings(str(output_file)))
    monkeypatch.setattr(debug_module.Path, "mkdir", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no dir")))

    with pytest.raises(PublishError, match="Cannot create log directory"):
        DebugFilePublisherAdapter()


def test_debug_file_publisher_raises_when_file_cannot_be_opened(tmp_path, monkeypatch):
    output_file = tmp_path / "debug_events.log"
    monkeypatch.setattr("config.settings.Settings.get_instance", lambda: DummySettings(str(output_file)))
    monkeypatch.setattr(debug_module.Path, "open", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no file")))

    with pytest.raises(PublishError, match="Cannot open debug log file"):
        DebugFilePublisherAdapter()


def test_debug_file_publisher_wraps_write_errors(mocker):
    publisher = object.__new__(DebugFilePublisherAdapter)
    publisher._file = mocker.Mock()
    publisher._file.write.side_effect = OSError("disk full")

    event = BashEvent(source="test-source", cmd="echo hello", action="command", severity_score=1)

    with pytest.raises(PublishError, match="write failed"):
        publisher.publish(event)


def test_debug_file_publisher_close_swallows_errors(mocker):
    publisher = object.__new__(DebugFilePublisherAdapter)
    publisher._file = mocker.Mock()
    publisher._file.close.side_effect = OSError("already closed")

    publisher.close()
