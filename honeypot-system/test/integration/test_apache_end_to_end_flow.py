import threading

from src.adapters.collectors.apache_log_collector_adapter import ApacheLogCollectorAdapter
from src.adapters.parsers.apache_parser_adapter import ApacheParserAdapter
from src.application.collector_thread import CollectorThread
from src.application.pipeline import Pipeline
from src.domain.models.event import GeoInfo
from src.ports.outbound.log_enricher_port import LogEnricher
from src.ports.outbound.publisher_port import Publisher


class InMemoryEnricher(LogEnricher):
    def enrich(self, entry):
        entry.enrichments.geolocation = GeoInfo(country="IT", city="Rome")
        return entry


class InMemoryPublisher(Publisher):
    def __init__(self):
        super().__init__()
        self.events = []

    def publish(self, entry):
        self.events.append(entry)


def test_apache_end_to_end_flow():
    collector = ApacheLogCollectorAdapter("/tmp/apache.log")
    collector.collect = lambda stop_event: iter(
        ['192.168.1.10 - admin [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.1" 200 1234']
    )
    publisher = InMemoryPublisher()
    pipeline = Pipeline(
        parsers={"apache": ApacheParserAdapter("/tmp/apache.log")},
        enrichers=[InMemoryEnricher()],
        publishers=[publisher],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()

    assert len(publisher.events) == 1
    event = publisher.events[0]
    assert event.source == "apache"
    assert event.ip == "192.168.1.10"
    assert event.user == "admin"
    assert event.method == "GET"
    assert event.path == "/login"
    assert event.status == 200
    assert event.size == 1234
    assert event.enrichments.geolocation.country == "IT"
    assert event.enrichments.geolocation.city == "Rome"
