import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.adapters.collectors.apache_log_collector_adapter import ApacheLogCollectorAdapter


def test_collect_returns_empty_when_file_missing(tmp_path):
    adapter = ApacheLogCollectorAdapter(str(tmp_path / "missing.log"))
    assert list(adapter.collect(threading.Event())) == []


def test_tail_file_yields_line_and_stops(monkeypatch):
    adapter = ApacheLogCollectorAdapter("/tmp/log")
    fake_file = MagicMock()
    fake_file.__enter__.return_value = fake_file
    fake_file.seek.return_value = None
    fake_file.readline.side_effect = ["hello\n", ""]

    monkeypatch.setattr("src.adapters.collectors.apache_log_collector_adapter.Path.open", lambda self, *args, **kwargs: fake_file)
    monkeypatch.setattr("src.adapters.collectors.apache_log_collector_adapter.time.sleep", lambda _: None)

    stop_event = threading.Event()
    generator = adapter.tail_file(Path("/tmp/log"), stop_event)
    assert next(generator) == "hello"

    stop_event.set()
    with pytest.raises(StopIteration):
        next(generator)
