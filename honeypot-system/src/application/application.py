"""
Application: Application
Top-level orchestrator. No longer implements an inbound port — main.py
depends on this class directly since there is only one driver.
"""

import threading

from src.application.director import Director
from src.factories.concrete_factories import (
    ConcreteLogParserFactory,
    ConcretePublisherFactory,
    ConcreteLogCollectorFactory,
    ConcreteLogEnricherFactory
)

from src.application.collector_thread import CollectorThread
from src.domain.exceptions.domain_exceptions import PipelineError
from src.infrastructure.logger import Logger


class Application:

    def __init__(
        self,
        services:        list[str],
        publishers:      list[str],
        collectors:      list[str],
        enrichment_tools: list[str],
    ) -> None:
        self._L               = Logger.get_instance()
        self._services        = services
        self._publishers      = publishers
        self._collectors      = collectors
        self._enrichment_tools = enrichment_tools
        self._threads:  list[CollectorThread]  = []
        self._stop_event: threading.Event      = threading.Event()

    def build_pipeline(self) -> None:
        self._L.info("Application: building pipeline ...")
        _director = Director(
            parser_factory    = ConcreteLogParserFactory(),
            publisher_factory = ConcretePublisherFactory(),
            collector_factory = ConcreteLogCollectorFactory(),
            enricher_factory  = ConcreteLogEnricherFactory(),
        )

        self._pipeline = _director.build(
            services   = self._services,
            publishers = self._publishers,
            collectors = self._collectors,
            enrichers  = self._enrichment_tools,
        )

        if self._pipeline.is_empty():
            raise PipelineError("Pipeline is empty — check your configuration.")
        self._L.info("Application: pipeline built successfully")

    def start_pipeline(self) -> None:
        self._L.info("=" * 60)
        self._L.info("  NullHive — Honeypot System")
        self._L.info("=" * 60)
        
        if self._pipeline.is_empty():
            raise PipelineError("Pipeline has not been built. Call build_pipeline() first.")

        self._stop_event.clear()
        self._threads.clear()

        for collector in self._pipeline.collectors:
            thread = CollectorThread(
                collector  = collector,
                pipeline   = self._pipeline,
                stop_event = self._stop_event,
            )
            self._threads.append(thread)
            thread.start()
            self._L.info("Started CollectorThread for %s", type(collector).__name__)

        self._L.info("Application: %d collector thread(s) running", len(self._threads))

    def stop_pipeline(self) -> None:
        self._L.info("Application: stopping pipeline ...")
        self._stop_event.set()

        for thread in self._threads:
            thread.join(timeout=10)
            if thread.is_alive():
                self._L.warning("CollectorThread did not stop in time: %s", thread.name)

        self._threads.clear()
        self._L.info("Application: pipeline stopped")