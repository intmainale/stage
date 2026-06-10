"""
Application: CollectorThread
One thread per LogCollector. Pulls raw lines from its collector, routes them
through the matching parser, applies all enrichers, then fans out to all publishers.
Now receives a Pipeline dataclass instead of a raw dict.
"""

import threading
from typing import Optional

from src.application.pipeline import Pipeline
from src.domain.exceptions.domain_exceptions import PipelineError

from src.domain.models.event import EnrichableEvent
from src.infrastructure.logger import Logger
from src.ports.outbound.log_collector_port import LogCollector


class CollectorThread(threading.Thread):

    def __init__(
        self,
        collector:  LogCollector,
        pipeline:   Pipeline,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        super().__init__(daemon=False)
        self._L         = Logger.get_instance()
        self._collector = collector
        self._pipeline  = pipeline
        self._stop_event = stop_event or threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        collector_name = type(self._collector).__name__ 
        self._L.debug(f"CollectorThread: started {collector_name} thread")
        
        parser_name = self._collector.parser_type
        try:
            parser = self._pipeline.parsers[parser_name]
            self._L.debug(f"CollectorThread: using parser '{parser_name}' for collector '{collector_name}'")
        except KeyError:
            raise PipelineError(f"CollectorThread: no parser found for type '{parser_name}'")
    
        for raw_line, path in self._collector.collect(self._stop_event):
            
            if self._stop_event.is_set():
                self._L.debug(f"CollectorThread: stopping {collector_name}")
                break
            
            event = parser.parse(raw_line, path)
            
            if event is not None and isinstance(event, EnrichableEvent):
                for enricher in self._pipeline.enrichers:
                    event = enricher.enrich(event)

            if event is not None:
                for publisher in self._pipeline.publishers:
                    publisher.publish(event)

        self._L.debug(f"CollectorThread: finished {collector_name} thread")
