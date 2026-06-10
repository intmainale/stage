"""
Application: Application
Top-level orchestrator. No longer implements an inbound port — main.py
depends on this class directly since there is only one driver.
"""

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
        logging_level:   int = 0
    ) -> None:
        self._L               = Logger.get_instance(level=logging_level)
        self._services        = services
        self._publishers      = publishers
        self._collectors      = collectors
        self._enrichment_tools = enrichment_tools
        self._pipeline: Pipeline = None
        self._threads:  list[CollectorThread]  = []
        self._stop_event: threading.Event      = threading.Event()

    
    def run(self) -> None:
        signal.signal(signal.SIGINT, self._shutdown_signal)
        signal.signal(signal.SIGTERM, self._shutdown_signal)

        try:
            self.build_pipeline()
            self.start_pipeline()

            self._stop_event.wait()  # Wait until stop event is set
        
        except ParseError as exc:
            self._L.error(f"Application: parse error — {exc}")
            self.stop_pipeline()
            sys.exit(1)
        
        except HoneypotError as exc:
            self._L.exception(f"Application: Fatal error")
            self.stop_pipeline()
            sys.exit(1)
            
        except Exception as exc:
            self._L.exception(f"Application: Unexpected error")
            self.stop_pipeline()
            sys.exit(1)
        
        finally:
            self._L.info("Application: exiting")
    
    def _shutdown_signal(self, signum, frame) -> None:
        self._L.info(f"Application: shutdown signal received: {signum}")
        self.stop_pipeline()

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
            self._L.debug(f"Application: started thread for {type(collector).__name__}")

        self._L.info(f"Application: {len(self._threads)} collector thread(s) running")


    def stop_pipeline(self) -> None:
        self._L.info("Application: stopping pipeline ...")
        self._stop_event.set()

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
