"""Adapter: BashLogCollector — streams lines from bash/auditd log files."""

from pathlib import Path
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError
from config.settings import Settings


class BashLogCollectorAdapter(LogCollector):
    """
    Reads bash history or a live audit log line-by-line.
    Configured via settings key: collectors.bash.path
    """

    DEFAULT_PATH = "/var/log/bash_history.log"

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._path = Path(cfg.get("collectors.bash.path", self.DEFAULT_PATH))

    def collect(self) -> Iterator[str]:
        self._L.info("BashLogCollectorAdapter: reading from %s", self._path)
        if not self._path.exists():
            self._L.warning("BashLogCollectorAdapter: file not found: %s", self._path)
            return

        try:
            with self._path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    yield line

        except OSError as exc:
            raise CollectionError(f"BashLogCollectorAdapter: read error: {exc}") from exc