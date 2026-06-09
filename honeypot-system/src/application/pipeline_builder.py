"""
Application: Pipeline Builder
Reads string-based config lists, calls the appropriate factory for each entry,
and populates a Pipeline.  Adding a new adapter type = new factory entry only,
zero changes here.
"""

from src.application.pipeline import Pipeline
from src.factories.abstract_factories import (
    LogParserFactory,
    PublisherFactory,
    LogCollectorFactory,
    LogEnricherFactory,
)
from src.infrastructure.logger import Logger


class PipelineBuilder:

    def __init__(
        self,
        parser_factory:    LogParserFactory,
        publisher_factory: PublisherFactory,
        collector_factory: LogCollectorFactory,
        enricher_factory:  LogEnricherFactory,
    ) -> None:
        self._L                = Logger.get_instance()
        self._parser_factory   = parser_factory
        self._publisher_factory      = publisher_factory
        self._collector_factory      = collector_factory
        self._enricher_factory      = enricher_factory

    def build(
        self,
        collectors: dict[str, dict],
        services:   list[str],
        enrichers:  list[str],
        publishers: list[str]
    ) -> Pipeline:
        """
        Iterate over each config list, delegate creation to the matching factory,
        and return a fully populated Pipeline.
        """
        pipeline = Pipeline()

        for name, config in collectors.items():
            paths = config.get("path", [])
            for path in paths:
                pipeline.add_collector(self._collector_factory.create_log_collector(name, path))
                self._L.debug(f"PipelineBuilder: added collector {name} with path {path}")

        for name in services:
            pipeline.add_parser(name, self._parser_factory.create_log_parser(name))
            self._L.debug(f"PipelineBuilder: added parser {name}")
        for name in enrichers:
            pipeline.add_enricher(self._enricher_factory.create_log_enricher(name))
            self._L.debug(f"PipelineBuilder: added enricher {name}")

        for name in publishers:
            pipeline.add_publisher(self._publisher_factory.create_publisher(name))
            self._L.debug(f"PipelineBuilder: added publisher {name}")

        self._L.info(
            f"PipelineBuilder: pipeline ready -- "
            f"parsers={len(pipeline.parsers)} "
            f"collectors={len(pipeline.collectors)} "
            f"enrichers={len(pipeline.enrichers)} "
            f"publishers={len(pipeline.publishers)}"
        )
        
        return pipeline
