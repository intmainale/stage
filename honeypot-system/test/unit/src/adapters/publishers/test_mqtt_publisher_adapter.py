import pytest

from src.adapters.publishers import mqtt_publisher_adapter as mqtt_module
from src.adapters.publishers.mqtt_publisher_adapter import MQTTPublisherAdapter
from src.domain.exceptions.domain_exceptions import PublishError
from src.domain.models.event import BashEvent


class DummySettings:
    def get(self, key: str, default=None):
        return default


def test_mqtt_publisher_dry_run_when_paho_unavailable(monkeypatch):
    monkeypatch.setattr("config.settings.Settings.get_instance", lambda: DummySettings())
    monkeypatch.setattr(mqtt_module, "_PAHO_AVAILABLE", False)

    publisher = MQTTPublisherAdapter()
    event = BashEvent(source="demo", cmd="ping", action="command", severity_score=1)
    event.host = "localhost"

    publisher.publish(event)


def test_mqtt_publisher_raises_on_bad_publish_rc(monkeypatch, mocker):
    class DummyClient:
        def connect(self, host, port, keepalive):
            pass

        def loop_start(self):
            pass

        def publish(self, topic, payload):
            return mocker.Mock(rc=1)

        def loop_stop(self):
            pass

        def disconnect(self):
            pass

    monkeypatch.setattr("config.settings.Settings.get_instance", lambda: DummySettings())
    monkeypatch.setattr(mqtt_module, "_PAHO_AVAILABLE", True)
    monkeypatch.setattr(mqtt_module.mqtt, "Client", DummyClient)

    publisher = MQTTPublisherAdapter()
    event = BashEvent(source="demo", cmd="ping", action="command", severity_score=1)
    event.host = "host1"

    with pytest.raises(PublishError):
        publisher.publish(event)