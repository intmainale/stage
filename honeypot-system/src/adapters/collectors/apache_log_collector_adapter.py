from pathlib import Path
import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError

class ApacheLogCollectorAdapter(LogCollector):
    """
    Tails Apache logs (access + error).
    Works on Debian 13 default paths.
    """

    DEFAULT_PATH = "/var/log/apache2/access.log"

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = Path(path) if path else Path(self.DEFAULT_PATH)
        
    def collect(self) -> Iterator[str]:
        self._L.info(f"ApacheLogCollectorAdapter {self.path}: reading from {self.path}")
        if not self.path.exists():
            self._L.warning(f"ApacheLogCollectorAdapter {self.path}: log not found: {self.path}")
            return
        try:
            yield from self.tail_file(self.path)

        except OSError as exc:
            raise CollectionError(f"ApacheLogCollectorAdapter {self.path}: read error: {exc}") from exc

    def tail_file(self, path: Path) -> Iterator[str]:
        """Tails a file and yields new lines as they are written."""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)  # Move to end of file

            while True:
                line = fh.readline()
                if line:
                    yield line.strip()
                else:
                    time.sleep(0.1)