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
from src.domain.exceptions.domain_exceptions import PublishError, SettingsError
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
        
        try:
            cfg = Settings.get_instance()

            self._file_path = Path(
                cfg.get("debug.output_path", "/var/log/eurosystem/debug_events.log")
            )
            # Ensure directory exists
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PublishError(f"DebugFilePublisherAdapter: cannot create log directory") from exc

        except KeyError as exc:
            raise SettingsError(f"DebugFilePublisherAdapter: failed to retrieve settings") from exc

        # Open in append mode (line-buffered behavior via flush)
        try:
            self._file = self._file_path.open("a", encoding="utf-8")
            self._L.info("DebugFilePublisher writing to %s", self._file_path)

        except OSError as exc:
            raise PublishError(f"DebugFilePublisherAdapter: cannot open debug log file") from exc

    def publish(self, entry: Event) -> None:
        try:
            payload = json.dumps(entry.to_dict(), default=str)

            self._file.write(payload + "\n")
            self._file.flush()  # ensure real-time visibility

            self._L.debug(f"DebugFilePublisherAdapter: wrote event source={entry.source}")

        except (OSError, TypeError, ValueError) as exc:
            raise PublishError(f"DebugFilePublisherAdapter: write failed") from exc

    def close(self) -> None:
        """Explicit cleanup for the debug file handle."""
        try:
            file = getattr(self, "_file", None)
            if file is not None:
                file.close()
                self._L.info("DebugFilePublisherAdapter: closed debug log file")
        except OSError as exc:
            raise PublishError(f"DebugFilePublisherAdapter: close failed") from exc
        finally:
            self._file = None
