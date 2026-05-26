import pytest

from src.adapters.collectors.journald_log_collector_adapter import JournaldLogCollectorAdapter
from src.domain.exceptions.domain_exceptions import CollectionError


class DummySettings:
    def __init__(self, unit: str, lines: str):
        self._unit = unit
        self._lines = lines

    def get(self, key: str, default=None):
        if key == "collectors.journald.unit":
            return self._unit
        if key == "collectors.journald.lines":
            return self._lines
        return default


def test_build_cmd_includes_unit(monkeypatch):
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings("ssh.service", "10"),
    )
    adapter = JournaldLogCollectorAdapter()
    assert "-u" in adapter._build_cmd()


def test_collect_yields_stdout_lines(monkeypatch, mocker):
    process = mocker.Mock()
    process.stdout = ["one\n", "two\n"]
    process.stderr = mocker.Mock()
    process.wait = mocker.Mock()
    process.returncode = 0

    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings("", "5"),
    )
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.subprocess.Popen",
        lambda *args, **kwargs: process,
    )

    adapter = JournaldLogCollectorAdapter()
    assert list(adapter.collect()) == ["one\n", "two\n"]


def test_collect_raises_collection_error_when_journalctl_missing(monkeypatch):
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings("", "5"),
    )
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.subprocess.Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )

    adapter = JournaldLogCollectorAdapter()
    with pytest.raises(Exception):
        list(adapter.collect())


def test_collect_raises_when_journalctl_returns_error(monkeypatch, mocker):
    process = mocker.Mock()
    process.stdout = []
    process.stderr.read.return_value = "journal failed"
    process.wait = mocker.Mock()
    process.returncode = 1

    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings("", "5"),
    )
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.subprocess.Popen",
        lambda *args, **kwargs: process,
    )

    adapter = JournaldLogCollectorAdapter()
    with pytest.raises(CollectionError, match="journalctl exited with 1"):
        list(adapter.collect())


def test_collect_wraps_os_errors(monkeypatch):
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.Settings.get_instance",
        lambda: DummySettings("", "5"),
    )
    monkeypatch.setattr(
        "src.adapters.collectors.journald_log_collector_adapter.subprocess.Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("cannot start")),
    )

    adapter = JournaldLogCollectorAdapter()
    with pytest.raises(CollectionError, match="OS error"):
        list(adapter.collect())
