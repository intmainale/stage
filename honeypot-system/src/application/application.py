"""
Application: Application
Top-level orchestrator. No longer implements an inbound port — main.py
depends on this class directly since there is only one driver.
"""

import logging
import sys
import threading
import signal

from src.application.pipeline import Pipeline
from src.application.pipeline_builder import PipelineBuilder
from src.application.collector_thread import CollectorThread
from src.factories.concrete_factories import (
    ConcreteLogParserFactory,
    ConcretePublisherFactory,
    ConcreteLogCollectorFactory,
    ConcreteLogEnricherFactory
)

from src.domain.exceptions.domain_exceptions import HoneypotError, PipelineError, ParseError
from src.infrastructure.logger import Logger


class Application:

    def __init__(
        self,
        collectors:      dict[str, str],
        services:        dict[str, str],
        enrichment_tools: list[str],
        publishers:      list[str],
    ) -> None:
        self._stopped = False
        self._services        = services
        self._publishers      = publishers
        self._collectors      = collectors
        self._enrichment_tools = enrichment_tools
        self._pipeline: Pipeline = None
        self._threads:  list[CollectorThread]  = []
        self._stop_event: threading.Event      = threading.Event()

    
    def run(self) -> int:

        try:
            status = self.configure()

            signal.signal(signal.SIGINT, self._shutdown_signal)
            signal.signal(signal.SIGTERM, self._shutdown_signal)

            if status != 0:
                return status
            self.build_pipeline()
            self.start_pipeline()
            self._stop_event.wait()
            self.stop_pipeline()
            print("Application: exiting")

            return 0
        
        except ParseError as exc:
            self._L.error(f"Application: parse error — {exc}")
            return 1
        
        except HoneypotError as exc:
            self._L.exception(f"Application: Fatal error")
            return 1
            
        except Exception as exc:
            self._L.exception(f"Application: Unexpected error")
            return 1


    def configure(self) -> int:
        print("Application: configuring ...")
        LOG_LEVELS = {
            "1": logging.DEBUG,
            "2": logging.INFO,
            "3": logging.WARNING,
            "4": logging.ERROR,
            "5": logging.CRITICAL,
        }

        print("""
        Select logging level:
        1 - DEBUG
        2 - INFO
        3 - WARNING
        4 - ERROR
        5 - CRITICAL
        """)

        try:
            choice = input("Enter choice (1-5) [default: 2]: ").strip()

            if not choice:
                print(f"Empty choice - default INFO")
                self._L = Logger.get_instance(level=logging.INFO)
                print("Application: configuration complete")
                return 0

        except KeyboardInterrupt:
            print("Startup interrupted (Ctrl+C) - shutting down")
            return 1

        except EOFError:
            print("Input closed (EOF) - shutting down")
            return 1

        if choice not in LOG_LEVELS:
            print(f"Invalid choice '{choice}' - default INFO")
            self._L = Logger.get_instance(level=logging.INFO)
            print("Application: configuration complete")
            return 0

        self._L = Logger.get_instance(level=LOG_LEVELS[choice])
        print("Application: configuration complete")
        return 0

    def build_pipeline(self) -> None:
        self._L.info("Application: building pipeline ...")
        pipeline_builder = PipelineBuilder(
            parser_factory    = ConcreteLogParserFactory(),
            publisher_factory = ConcretePublisherFactory(),
            collector_factory = ConcreteLogCollectorFactory(),
            enricher_factory  = ConcreteLogEnricherFactory(),
        )

        self._pipeline = pipeline_builder.build(
            services   = self._services,
            publishers = self._publishers,
            collectors = self._collectors,
            enrichers  = self._enrichment_tools,
        )

        if self._pipeline.is_empty():
            raise PipelineError("Application: pipeline is empty — check your configuration.")
        
        self._L.info("Application: pipeline built successfully")

    def start_pipeline(self) -> None:
        self._L.info("=" * 60)
        self._L.info("  NullHive — Honeypot System")
        self._L.info("=" * 60)
        
        if self._pipeline is None or self._pipeline.is_empty():
            raise PipelineError("Application: pipeline has not been built")

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

        self._L.info(f"Application: {len(self._threads)} collector thread(s) running")


    def stop_pipeline(self) -> None:
        if self._stopped:
            return

        self._L.info("Application: stopping pipeline ...")
        self._stop_event.set()
        self._stopped = True

        for thread in self._threads:
            thread.join(timeout=10)
            if thread.is_alive():
                self._L.warning(f"Application: thread did not stop in time: {thread.name}")

        if self._pipeline is not None:
            for publisher in self._pipeline.publishers:
                self._L.debug(f"Application: closing publisher {type(publisher).__name__}")
                publisher.close()
                
        self._threads.clear()
        self._L.info("Application: pipeline stopped")

    def _shutdown_signal(self, signum, frame) -> None:
        print(f"Application: shutdown signal received: {signum}")
        self._stop_event.set()