"""Adapter: AuditdLogCollector — streams lines from /var/log/audit/audit.log."""

from pathlib import Path
import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError
from config.settings import Settings


class AuditdLogCollectorAdapter(LogCollector):
    """
    Reads the Linux auditd log file.
    Configured via settings key: collectors.auditd.path
    """

    DEFAULT_PATH = "/var/log/audit/audit.log"

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._path = Path(cfg.get("collectors.auditd.path", self.DEFAULT_PATH))

    def collect(self) -> Iterator[str]:
        self._L.info("AuditdLogCollectorAdapter: reading from %s", self._path)
        if not self._path.exists():
            self._L.warning("AuditdLogCollectorAdapter: file not found: %s", self._path)
            return

        try:
            yield from self._tail_file(self._path)
                    
        except OSError as exc:
            raise CollectionError(f"AuditdLogCollectorAdapter: read error: {exc}") from exc
    
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