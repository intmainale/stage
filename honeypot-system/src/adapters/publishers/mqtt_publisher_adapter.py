"""
Adapter: MQTTPublisher
Publishes Event objects to an MQTT broker as JSON payloads.
Requires paho-mqtt; falls back to a stub when the library is absent.
"""

import json
from typing import Any

from src.ports.outbound.publisher_port import Publisher
from src.domain.models.event import Event
from src.domain.exceptions.domain_exceptions import PublishError
from config.settings import Settings

try:
    import paho.mqtt.client as mqtt  # type: ignore
    _PAHO_AVAILABLE = True
except ImportError:
    _PAHO_AVAILABLE = False


class MQTTPublisherAdapter(Publisher):
    """
    Publishes each Event as a JSON message to an MQTT topic.
    Topic pattern: eurosystem/<source>/<host>
    """

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._host:  str = cfg.get("mqtt.host",  "localhost")
        self._port:  int = int(cfg.get("mqtt.port",  "1883"))
        self._topic: str = cfg.get("mqtt.topic", "eurosystem/logs")
        self._client: Any = None

        if _PAHO_AVAILABLE:
            self._client = mqtt.Client()

            try:
                self._client.connect(self._host, self._port, keepalive=60)
                self._client.loop_start()
                self._L.info("MQTTPublisher connected to %s:%d", self._host, self._port)

            except Exception as exc:  # noqa: BLE001
                self._L.warning("MQTTPublisher: could not connect: %s", exc)
                self._client = None
        else:
            self._L.warning("MQTTPublisher: paho-mqtt not installed — running in dry-run mode")

    def publish(self, entry: Event) -> None:
        topic   = f"{self._topic}/{entry.source}/{entry.host or 'unknown'}"
        payload = json.dumps(entry.to_dict(), default=str)

        if self._client is not None:
            result = self._client.publish(topic, payload)
            if result.rc != 0:
                raise PublishError(f"MQTT publish failed with rc={result.rc}")
            self._L.debug("MQTTPublisher: published to %s", topic)
        else:
            # Dry-run: just log the payload
            self._L.info("MQTTPublisher [dry-run] → %s : %s", topic, payload[:120])

    def __del__(self) -> None:
        if self._client is not None:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass