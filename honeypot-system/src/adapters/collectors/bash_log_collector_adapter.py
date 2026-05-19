"""Adapter: BashLogCollector — streams lines from bash/auditd log files."""

from pathlib import Path
from time import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError
from config.settings import Settings


class BashLogCollectorAdapter(LogCollector):
    """
    Reads bash history line-by-line.
    Configured via settings key: collectors.bash.path
    Log structure: 2026-05-15T10:42:11 path=/home/alex user=alex uid=1000 groups=admin,docker pid=4242 ppid=4110 exe=bash cmd="ls -la"
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
            yield from self._tail_file(self._path)

        except OSError as exc:
            raise CollectionError(f"BashLogCollectorAdapter: read error: {exc}") from exc
    
    def _tail_file(self, path: Path) -> Iterator[str]:
        """Tails a file and yields new lines as they are written."""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)  # Move to end of file

            while True:
                line = fh.readline()
                if line:
                    yield line.strip()
                else:
                    time.sleep(0.1)