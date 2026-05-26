from src.ports.outbound.publisher_port import Publisher
from src.domain.models.event import Event


class DummyPublisher(Publisher):
    def publish(self, entry: Event):
        super().publish(entry)
        self.published = getattr(self, "published", [])
        self.published.append(entry)


def test_publisher_base_publish_is_callable():
    publisher = DummyPublisher()
    event = Event(source="publisher-test")
    publisher.publish(event)
    assert event in publisher.published
