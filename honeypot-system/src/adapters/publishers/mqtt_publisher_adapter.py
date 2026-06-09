"""
Adapter: MQTTPublisher
Publishes Event objects to an MQTT broker as JSON payloads.
Requires paho-mqtt; falls back to a stub when the library is absent.
"""
 
import json
from typing import Any

from src.ports.outbound.publisher_port import Publisher
from src.domain.models.event import Event
from src.domain.exceptions.domain_exceptions import PublishError, SettingsError
from config.settings import Settings

import paho.mqtt.client as mqtt



class MQTTPublisherAdapter(Publisher):
    """
    Publishes each Event as a flat JSON message to an MQTT topic.
    Topic pattern: {topic_prefix}/{event.source}
    """

    def __init__(self) -> None:
        super().__init__()
        try:
            cfg = Settings.get_instance()
            self._host:  str = cfg.get("mqtt.host",  "localhost")
            self._port:  int = int(cfg.get("mqtt.port",  "1883"))
            self._topic: str = cfg.get("mqtt.topic_prefix", "logs")
        except KeyError as exc:
            raise SettingsError("MQTTPublisherAdapter: failed to retrieve settings") from exc
        
        self._client: Any = None

        try:
            self._client = mqtt.Client()
            self._client.connect(self._host, self._port, keepalive=60)
            self._client.loop_start()
            self._L.info(f"MQTTPublisherAdapter connected to {self._host}:{self._port}")

        except (OSError, ValueError, RuntimeError) as exc:
            self._client = None
            raise PublishError(f"MQTTPublisherAdapter: could not connect to {self._host}:{self._port}") from exc

    def publish(self, entry: Event) -> None:
        topic   = f"{self._topic}/{entry.source}"
        payload = json.dumps(entry.to_dict(), default=str)

        if self._client is not None:
            result = self._client.publish(topic, payload)
            if result.rc != 0:
                raise PublishError(f"MQTTPublisherAdapter: publish failed with rc={result.rc}")
            self._L.debug(f"MQTTPublisherAdapter: published to {topic}")
            return

        raise PublishError("MQTTPublisherAdapter: client is not connected")

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.loop_stop()
                self._client.disconnect()
                self._L.info("MQTTPublisherAdapter: connection closed")
            except (OSError, RuntimeError, ValueError) as exc:
                raise PublishError(f"MQTTPublisherAdapter: connection close failed") from exc
            finally:
                self._client = None
