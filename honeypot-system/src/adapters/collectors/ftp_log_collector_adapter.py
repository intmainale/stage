from pathlib import Path
import threading
import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError


class FtpLogCollectorAdapter(LogCollector):
    """
    Tails ProFTPD 1.3.5 logs.
    The service has CVE-2015-3306.
    """

    DEFAULT_PATH = "/var/log/extended.log"

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = Path(path) if path else Path(self.DEFAULT_PATH)

    def collect(self, stop_event: threading.Event) -> Iterator[str]:
        self._L.info(f"FtpLogCollectorAdapter {self.path}: reading from {self.path}")

        if not self.path.exists():
            self._L.warning(f"FtpLogCollectorAdapter {self.path}: log not found: {self.path}")
            return

        try:
            yield from self.tail_file(self.path, stop_event)

        except OSError as exc:
            raise CollectionError(f"FtpLogCollectorAdapter {self.path}: read error: {exc}") from exc

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
