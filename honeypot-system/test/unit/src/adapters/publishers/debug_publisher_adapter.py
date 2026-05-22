import json
from pathlib import Path

from src.adapters.publishers.debug_publisher_adapter import DebugFilePublisherAdapter
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
