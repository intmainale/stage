from pathlib import Path
import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError
from config.settings import Settings

class ApacheLogCollectorAdapter(LogCollector):
    """
    Tails Apache logs (access + error).
    Works on Debian 13 default paths.
    """

    DEFAULT_PATHS = {
        "access": "/var/log/apache2/access.log",
        "error": "/var/log/apache2/error.log",
    }
    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self.access_log = Path(cfg.get("collectors.apache.access_path", self.DEFAULT_PATHS["access"]))
        self.error_log = Path(cfg.get("collectors.apache.error_path", self.DEFAULT_PATHS["error"]))

    def collect(self) -> Iterator[str]:
        self._L.info("ApacheLogCollectorAdapter: reading from %s and %s", self.access_log, self.error_log)
        if not self.access_log.exists():
            self._L.warning("ApacheLogCollectorAdapter: access log not found: %s", self.access_log)
        if not self.error_log.exists():
            self._L.warning("ApacheLogCollectorAdapter: error log not found: %s", self.error_log)

        # For simplicity, we read existing lines once and then switch to async tailing.
        # In a real implementation, we might want to handle file rotation and other edge cases.

        try:
            if self.access_log.exists():
                yield from self._tail_file(self.access_log, "access")

            if self.error_log.exists():
                yield from self._tail_file(self.error_log, "error")
                    
        except OSError as exc:
            raise CollectionError(f"ApacheLogCollectorAdapter: read error: {exc}") from exc
        
    def _tail_file(self, path: Path, source: str) -> Iterator[str]:
        """Tails a file and yields new lines as they are written."""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)  # Move to end of file

            while True:
                line = fh.readline()
                if line:
                    yield f"{source}: {line.strip()}"
                else:
                    time.sleep(0.1)