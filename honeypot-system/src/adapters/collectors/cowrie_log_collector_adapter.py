from pathlib import Path
import threading
import time
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError


class CowrieLogCollectorAdapter(LogCollector):
    """
    Tails Cowrie JSON logs.

    Default:
        /home/cowrie/cowrie/var/log/cowrie/cowrie.json

    Yields:
        (raw_json_line, path)
    """

    DEFAULT_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

    def __init__(self, path: str | None, parser_type: str) -> None:
        super().__init__()

        self.path = Path(path) if path else Path(self.DEFAULT_PATH)
        self.parser_type = parser_type

    def collect(
        self,
        stop_event: threading.Event,
    ) -> Iterator[tuple[str, str]]:
        self._L.info(
            "CowrieLogCollectorAdapter: reading from %s",
            self.path,
        )

        if not self.path.exists():
            raise CollectionError(
                f"CowrieLogCollectorAdapter: file not found: {self.path}"
            )

        try:
            yield from self.tail_file(
                self.path,
                stop_event,
            )

        except OSError as exc:
            raise CollectionError(
                f"CowrieLogCollectorAdapter: read error for {self.path}"
            ) from exc

    def tail_file(
        self,
        path: Path,
        stop_event: threading.Event,
    ) -> Iterator[tuple[str, str]]:
        """
        Tail Cowrie JSON log file.

        Every line is already a complete JSON event.
        """

        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as fh:

            # Start at end (live mode)
            fh.seek(0, 2)

            while not stop_event.is_set():

                line = fh.readline()

                if line:

                    line = line.strip()

                    if not line:
                        continue

                    self._L.debug(
                        "CowrieLogCollectorAdapter: read JSON event from %s",
                        path,
                    )

                    yield line, str(path)

                else:
                    time.sleep(0.1)