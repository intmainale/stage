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

    def __init__(self, path: str, parser_type: str) -> None:
        super().__init__()
        self.path = Path(path) if path else Path(self.DEFAULT_PATH)
        self.parser_type = parser_type

    def collect(self, stop_event: threading.Event) -> Iterator[tuple[str, str]]:
        self._L.info("FtpLogCollectorAdapter: reading from %s", self.path)

        if not self.path.exists():
            raise CollectionError(f"FtpLogCollectorAdapter: file not found: {self.path}")

        try:
            yield from self.tail_file(self.path, stop_event)

        except OSError as exc:
            raise CollectionError(f"FtpLogCollectorAdapter: read error for {self.path}") from exc

    def tail_file(self, path: Path, stop_event: threading.Event) -> Iterator[tuple[str, str]]:
        """Tails a file and yields new lines as they are written."""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)  # Move to end of file

            while not stop_event.is_set():
                
                line = fh.readline()
                if line:
                    self._L.debug("FtpLogCollectorAdapter: read line from %s: %s", path, line.strip())
                    yield line.strip(), str(path)
                else:
                    time.sleep(0.1)
