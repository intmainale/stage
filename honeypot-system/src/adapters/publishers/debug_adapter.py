"""
Adapter: DebugFilePublisher
Writes Event objects as JSON lines to a local file (Linux-friendly).
Used for debugging pipelines instead of MQTT.
"""

import json
from pathlib import Path
from typing import Any

from src.ports.outbound.publisher_port import Publisher
from src.domain.models.event import Event
from src.domain.exceptions.domain_exceptions import PublishError
from config.settings import Settings


class DebugFilePublisherAdapter(Publisher):
    """
    Writes each Event as a JSON line (NDJSON format).

    Output format:
        one event per line
        easy to tail -f / inspect / ingest later
    """

    def __init__(self) -> None:
        super().__init__()

        cfg = Settings.get_instance()

        self._file_path = Path(
            cfg.get("debug.output_path", "/var/log/eurosystem/debug_events.log")
        )

        # Ensure directory exists
        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise PublishError(f"Cannot create log directory: {exc}") from exc

        # Open in append mode (line-buffered behavior via flush)
        try:
            self._file = self._file_path.open("a", encoding="utf-8")
            self._L.info("DebugFilePublisher writing to %s", self._file_path)

        except OSError as exc:
            raise PublishError(f"Cannot open debug log file: {exc}") from exc

    def publish(self, entry: Event) -> None:
        try:
            payload = json.dumps(entry.to_dict(), default=str)

            self._file.write(payload + "\n")
            self._file.flush()  # ensure real-time visibility

            self._L.debug(
                "DebugFilePublisher: wrote event source=%s host=%s",
                entry.source,
                entry.host,
            )

        except Exception as exc:
            raise PublishError(f"DebugFilePublisher write failed: {exc}") from exc

    def close(self) -> None:
        """
        Explicit cleanup (better than relying on __del__).
        """
        try:
            if hasattr(self, "_file") and self._file:
                self._file.close()
        except Exception:
            pass

    def __del__(self) -> None:
        self.close()