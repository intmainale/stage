from pathlib import Path

import pytest

from src.adapters.collectors.ftp_log_collector_adapter import FtpLogCollectorAdapter
from src.domain.exceptions.domain_exceptions import CollectionError


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key == "collectors.ftp.path":
            return self._value
        return default


def test_collect_returns_empty_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.adapters.collectors.ftp_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings(str(tmp_path / "missing.log")),
    )

    adapter = FtpLogCollectorAdapter()
    assert list(adapter.collect()) == []


def test_tail_file_yields_line_and_stops(monkeypatch, mocker):
    monkeypatch.setattr(
        "src.adapters.collectors.ftp_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings("/tmp/log"),
    )

    adapter = FtpLogCollectorAdapter()
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

    generator = adapter._tail_file(Path("/tmp/log"))
    assert next(generator) == "ftp line"
    with pytest.raises(StopTail):
        next(generator)


def test_collect_wraps_os_errors(tmp_path, monkeypatch):
    log_file = tmp_path / "ftp.log"
    log_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        "src.adapters.collectors.ftp_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings(str(log_file)),
    )
    adapter = FtpLogCollectorAdapter()

    def raise_os_error(path):
        raise OSError("cannot read")
        yield

    monkeypatch.setattr(adapter, "_tail_file", raise_os_error)

    with pytest.raises(CollectionError, match="FTP collector error"):
        list(adapter.collect())
