import threading
from pathlib import Path

import pytest

from src.adapters.collectors.bash_log_collector_adapter import BashLogCollectorAdapter
from src.domain.exceptions.domain_exceptions import CollectionError


def test_collect_returns_empty_when_file_missing(tmp_path):
    adapter = BashLogCollectorAdapter(str(tmp_path / "missing.log"))
    assert list(adapter.collect(threading.Event())) == []


def test_tail_file_yields_line_and_stops(monkeypatch, mocker):
    adapter = BashLogCollectorAdapter(str(Path("/tmp/log")))
    fake_file = mocker.MagicMock()
    fake_file.__enter__.return_value = fake_file
    fake_file.seek.return_value = None
    fake_file.readline.side_effect = ["bash line\n", ""]

    monkeypatch.setattr("src.adapters.collectors.bash_log_collector_adapter.Path.open", lambda self, *args, **kwargs: fake_file)
    monkeypatch.setattr("src.adapters.collectors.bash_log_collector_adapter.time.sleep", lambda _: None)

    stop_event = threading.Event()
    generator = adapter.tail_file(Path("/tmp/log"), stop_event)
    assert next(generator) == "bash line"

    stop_event.set()
    with pytest.raises(StopIteration):
        next(generator)


def test_collect_wraps_os_errors(tmp_path, monkeypatch):
    log_file = tmp_path / "bash.log"
    log_file.write_text("", encoding="utf-8")
    adapter = BashLogCollectorAdapter(str(log_file))

    def raise_os_error(path, stop_event):
        raise OSError("cannot read")
        yield

    monkeypatch.setattr(adapter, "tail_file", raise_os_error)

    with pytest.raises(CollectionError, match="read error"):
        list(adapter.collect(threading.Event()))
