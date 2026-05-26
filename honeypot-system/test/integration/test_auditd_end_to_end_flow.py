import threading

from src.adapters.collectors.auditd_log_collector_adapter import AuditdLogCollectorAdapter
from src.adapters.parsers.auditd_parser_adapter import AuditdParserAdapter
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


def test_auditd_end_to_end_flow():
    collector = AuditdLogCollectorAdapter("/tmp/audit.log")
    collector.collect = lambda stop_event: iter(
        [
            'type=SYSCALL msg=audit(1716112345.123:456): arch=c000003e syscall=59 '
            'success=yes exe="/usr/bin/curl" comm="curl" pid=1234 uid=1000 ppid=5678'
        ]
    )
    enricher = InMemoryEnricher()
    publisher = InMemoryPublisher()
    pipeline = Pipeline(
        parsers={"auditd": AuditdParserAdapter("/tmp/audit.log")},
        enrichers=[enricher],
        publishers=[publisher],
    )

    CollectorThread(collector, pipeline, threading.Event()).run()

    assert len(enricher.entries) == 0
    assert len(publisher.events) == 1
    event = publisher.events[0]
    assert event.source == "auditd"
    assert event.event_id == 456
    assert event.pid == 1234
    assert event.ppid == 5678
    assert event.uid == 1000
    assert event.exe == "/usr/bin/curl"
    assert event.comm == "curl"
    assert event.success is True
    assert event.syscall == "59"
