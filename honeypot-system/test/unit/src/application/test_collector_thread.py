import threading

from src.application.collector_thread import CollectorThread
from src.application.pipeline import Pipeline
from src.adapters.collectors.apache_log_collector_adapter import ApacheLogCollectorAdapter
from src.adapters.collectors.auditd_log_collector_adapter import AuditdLogCollectorAdapter
from src.adapters.collectors.bash_log_collector_adapter import BashLogCollectorAdapter
from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError, EnrichmentError, ParseError, PublishError
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


class FailingEnricher:
    def enrich(self, entry):
        raise EnrichmentError("enrich failed")


class DummyPublisher:
    def __init__(self):
        self.published = []

    def publish(self, entry):
        self.published.append(entry)


class FailingPublisher:
    def publish(self, entry):
        raise PublishError("publish failed")


class UnknownCollector(LogCollector):
    def collect(self, stop_event=None):
        return iter(["ignored"])


class FailingCollector(LogCollector):
    def collect(self, stop_event=None):
        raise CollectionError("collection failed")


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


def test_collector_thread_routes_bash_collector_to_bash_parser():
    collector = BashLogCollectorAdapter("/tmp/log")
    collector.collect = lambda stop_event: iter(["raw line"])

    publisher = DummyPublisher()
    pipeline = Pipeline(
        parsers={"bash": DummyParser()},
        enrichers=[],
        publishers=[publisher],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()

    assert len(publisher.published) == 1


def test_collector_thread_routes_auditd_collector_to_auditd_parser():
    collector = AuditdLogCollectorAdapter("/tmp/log")
    collector.collect = lambda stop_event: iter(["raw line"])

    publisher = DummyPublisher()
    pipeline = Pipeline(
        parsers={"auditd": DummyParser()},
        enrichers=[],
        publishers=[publisher],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()

    assert len(publisher.published) == 1


def test_collector_thread_continues_when_enricher_fails():
    collector = ApacheLogCollectorAdapter("/tmp/log")
    collector.collect = lambda stop_event: iter(["raw line"])

    publisher = DummyPublisher()
    pipeline = Pipeline(
        parsers={"apache": DummyParser()},
        enrichers=[FailingEnricher()],
        publishers=[publisher],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()

    assert len(publisher.published) == 1


def test_collector_thread_handles_publisher_errors_without_crash():
    collector = ApacheLogCollectorAdapter("/tmp/log")
    collector.collect = lambda stop_event: iter(["raw line"])

    pipeline = Pipeline(
        parsers={"apache": DummyParser()},
        enrichers=[],
        publishers=[FailingPublisher()],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()


def test_collector_thread_handles_collection_errors_without_crash():
    pipeline = Pipeline(parsers={}, enrichers=[], publishers=[])
    CollectorThread(FailingCollector(), pipeline, threading.Event()).run()
