from pathlib import Path
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError
from config.settings import Settings
import time


class FtpLogCollectorAdapter(LogCollector):
    """
    Tails FTP logs (vsftpd/proftpd style).
    Works on Debian 13 typical setups.
    """

    DEFAULT_PATH = "/var/log/vsftpd.log"

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()

        self.ftp_log = Path(cfg.get("collectors.ftp.path", self.DEFAULT_PATH))

    def collect(self) -> Iterator[str]:
        self._L.info("FtpLogCollectorAdapter: reading from %s", self.ftp_log)

        if not self.ftp_log.exists():
            self._L.warning("FtpLogCollectorAdapter: log not found: %s", self.ftp_log)
            return

        try:
            yield from self._tail_file(self.ftp_log)

        except OSError as exc:
            raise CollectionError(f"FTP collector error: {exc}") from exc

    def _tail_file(self, path: Path) -> Iterator[str]:
        """
        Simple tail -f implementation (thread-friendly).
        """

        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # jump to end

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.2)
                    continue

                yield line.strip()