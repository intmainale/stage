"""
Application: CollectorThread
One thread per LogCollector. Pulls raw lines from its collector, routes them
through the matching parser, applies all enrichers, then fans out to all publishers.
Now receives a Pipeline dataclass instead of a raw dict.
"""

import threading
from typing import Optional

from src.application.pipeline import Pipeline
from src.domain.exceptions.domain_exceptions import (
    ParseError, CollectionError, PublishError, EnrichmentError,
)
from src.infrastructure.logger import Logger
from src.ports.outbound.log_collector_port import LogCollector

from src.adapters.collectors.apache_log_collector_adapter import ApacheLogCollectorAdapter
from src.adapters.collectors.bash_log_collector_adapter import BashLogCollectorAdapter
from src.adapters.collectors.auditd_log_collector_adapter import AuditdLogCollectorAdapter

class CollectorThread(threading.Thread):

    def __init__(
        self,
        collector:  LogCollector,
        pipeline:   Pipeline,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        super().__init__(daemon=True)
        self._L         = Logger.get_instance()
        self._collector = collector
        self._pipeline  = pipeline
        self._stop_event = stop_event or threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        collector_name = type(self._collector).__name__
        self._L.info("CollectorThread started: %s", collector_name)

        try:
            for raw_line in self._collector.collect():
                
                if self._stop_event.is_set():
                    self._L.info("CollectorThread stopping: %s", collector_name)
                    break
                event = None

                if isinstance(self._collector, ApacheLogCollectorAdapter):
                    try:
                        event = self._pipeline.parsers["apache"].parse(raw_line)
                    except ParseError as exc:
                        self._L.error("Parse error [%s]: %s", "apache", exc)
                    
                    if event is not None:
                        for enricher in self._pipeline.enrichers:
                            try:
                                event = enricher.enrich(event)
                            except EnrichmentError as exc:
                                self._L.warning("Enrichment error [%s]: %s", type(enricher).__name__, exc)

                elif isinstance(self._collector, BashLogCollectorAdapter):
                    try:
                        event = self._pipeline.parsers["bash"].parse(raw_line)
                    except ParseError as exc:
                        self._L.error("Parse error [%s]: %s", "bash", exc)

                elif isinstance(self._collector, AuditdLogCollectorAdapter):
                    try:
                        event = self._pipeline.parsers["auditd"].parse(raw_line)
                    except ParseError as exc:
                        self._L.error("Parse error [%s]: %s", "auditd", exc)
                
                else:
                    raise ParseError(f"No parser found for collector type: {type(self._collector).__name__}")
                
                if event is not None:
                    for publisher in self._pipeline.publishers:
                        try:
                            publisher.publish(event)
                        except PublishError as exc:
                            self._L.error("Publish error [%s]: %s", type(publisher).__name__, exc)

        except CollectionError as exc:
            self._L.error("CollectorThread [%s] fatal collection error: %s", collector_name, exc)
        except Exception as exc:
            self._L.exception("CollectorThread [%s] unexpected error: %s", collector_name, exc)
        finally:
            self._L.info("CollectorThread finished: %s", collector_name)