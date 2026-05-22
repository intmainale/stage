import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.adapters.collectors.auditd_log_collector_adapter import AuditdLogCollectorAdapter


def test_collect_returns_empty_when_file_missing(tmp_path):
    adapter = AuditdLogCollectorAdapter(str(tmp_path / "missing.log"))
    assert list(adapter.collect(threading.Event())) == []


def test_tail_file_yields_line_and_stops(monkeypatch):
    adapter = AuditdLogCollectorAdapter(str(Path("/tmp/log")))
    fake_file = MagicMock()
    fake_file.__enter__.return_value = fake_file
    fake_file.seek.return_value = None
    fake_file.readline.side_effect = ["audit line\n", ""]

    monkeypatch.setattr("src.adapters.collectors.auditd_log_collector_adapter.Path.open", lambda self, *args, **kwargs: fake_file)
    monkeypatch.setattr("src.adapters.collectors.auditd_log_collector_adapter.time.sleep", lambda _: None)

    stop_event = threading.Event()
    generator = adapter.tail_file(Path("/tmp/log"), stop_event)
    assert next(generator) == "audit line"

    stop_event.set()
    with pytest.raises(StopIteration):
        next(generator)
