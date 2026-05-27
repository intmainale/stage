from pathlib import Path
import threading

import pytest

from src.adapters.collectors.ftp_log_collector_adapter import FtpLogCollectorAdapter
from src.domain.exceptions.domain_exceptions import CollectionError


def test_collect_returns_empty_when_file_missing(tmp_path):
    adapter = FtpLogCollectorAdapter(str(tmp_path / "missing.log"))
    assert list(adapter.collect(threading.Event())) == []


def test_tail_file_yields_line_and_stops(monkeypatch, mocker):
    adapter = FtpLogCollectorAdapter("/tmp/log")
    fake_file = mocker.MagicMock()
    fake_file.__enter__.return_value = fake_file
    fake_file.seek.return_value = None
    fake_file.readline.side_effect = ["ftp line\n", ""]

    monkeypatch.setattr("src.adapters.collectors.ftp_log_collector_adapter.Path.open", lambda self, *args, **kwargs: fake_file)

    class StopTail(Exception):
        pass

    def fake_sleep(_):
        raise StopTail

    monkeypatch.setattr("src.adapters.collectors.ftp_log_collector_adapter.time.sleep", fake_sleep)

    generator = adapter.tail_file(Path("/tmp/log"), threading.Event())
    assert next(generator) == "ftp line"
    with pytest.raises(StopTail):
        next(generator)


def test_collect_wraps_os_errors(tmp_path, monkeypatch):
    log_file = tmp_path / "ftp.log"
    log_file.write_text("", encoding="utf-8")
    adapter = FtpLogCollectorAdapter(str(log_file))

    def raise_os_error(path, stop_event):
        raise OSError("cannot read")
        yield

    monkeypatch.setattr(adapter, "tail_file", raise_os_error)

    with pytest.raises(CollectionError, match="FtpLogCollectorAdapter"):
        list(adapter.collect(threading.Event()))
