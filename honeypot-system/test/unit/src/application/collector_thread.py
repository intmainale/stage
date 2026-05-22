import threading
from unittest.mock import Mock

from src.application.collector_thread import CollectorThread
from src.application.pipeline import Pipeline
from src.adapters.collectors.apache_log_collector_adapter import ApacheLogCollectorAdapter
from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import ParseError
from src.domain.models.event import EnrichableEvent


class DummyParser:
    def parse(self, raw_line: str):
        return EnrichableEvent(ip="1.2.3.4")


class FailingParser:
    def parse(self, raw_line: str):
        raise ParseError("parse failed")


class DummyEnricher:
    def enrich(self, entry):
        entry.ip = "5.6.7.8"
        return entry


class DummyPublisher:
    def __init__(self):
        self.published = []

    def publish(self, entry):
        self.published.append(entry)


class UnknownCollector(LogCollector):
    def collect(self, stop_event=None):
        return iter(["ignored"])


def test_collector_thread_parses_enriches_and_publishes_message():
    collector = ApacheLogCollectorAdapter("/tmp/log")
    collector.collect = lambda stop_event: iter(["raw line"])

    publisher = DummyPublisher()
    pipeline = Pipeline(
        parsers={"apache": DummyParser()},
        enrichers=[DummyEnricher()],
        publishers=[publisher],
    )

    thread = CollectorThread(collector, pipeline, threading.Event())
    thread.run()

    assert len(publisher.published) == 1
    assert publisher.published[0].ip == "5.6.7.8"


def test_collector_thread_handles_parse_errors_gracefully():
    collector = ApacheLogCollectorAdapter("/tmp/log")
    collector.collect = lambda stop_event: iter(["raw line"])

    pipeline = Pipeline(parsers={"apache": FailingParser()}, enrichers=[], publishers=[])
    thread = CollectorThread(collector, pipeline, threading.Event())
    thread.run()


def test_collector_thread_handles_unknown_collector_type_without_crash():
    pipeline = Pipeline(parsers={}, enrichers=[], publishers=[])
    thread = CollectorThread(UnknownCollector(), pipeline, threading.Event())
    thread.run()
