"""Adapter: AuditdLogCollector — streams lines from /var/log/audit/audit.log."""

from pathlib import Path
import threading
import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError


class AuditdLogCollectorAdapter(LogCollector):
    """
    Reads the Linux auditd log file.
    Configured via settings key: collectors.auditd.path
    """

    DEFAULT_PATH = "/var/log/audit/audit.log"

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = Path(path) if path else Path(self.DEFAULT_PATH)

    def collect(self, stop_event: threading.Event) -> Iterator[str]:
        self._L.info(f"AuditdLogCollectorAdapter {self._path}: reading from {self._path}")
        if not self._path.exists():
            self._L.warning(f"AuditdLogCollectorAdapter {self._path}: file not found: {self._path}")
            return

        try:
            yield from self.tail_file(self._path, stop_event)
                    
        except OSError as exc:
            raise CollectionError(f"AuditdLogCollectorAdapter {self._path}: read error: {exc}") from exc

    def tail_file(self, path: Path, stop_event: threading.Event) -> Iterator[str]:
        """Tails a file and yields new lines as they are written."""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)  # Move to end of file

            while not stop_event.is_set():
                line = fh.readline()
                if line:
                    yield line.strip()
                else:
                    time.sleep(0.1)