"""
Application: Director
Reads string-based config lists, calls the appropriate factory for each entry,
and populates a Pipeline.  Adding a new adapter type = new factory entry only,
zero changes here.
"""
from __future__ import annotations

from src.application.pipeline import Pipeline
from src.factories.abstract_factories import (
    LogParserFactory,
    PublisherFactory,
    LogCollectorFactory,
    LogEnricherFactory,
)
from src.infrastructure.logger import Logger


class Director:

    def __init__(
        self,
        parser_factory:    LogParserFactory,
        publisher_factory: PublisherFactory,
        collector_factory: LogCollectorFactory,
        enricher_factory:  LogEnricherFactory,
    ) -> None:
        self._L                = Logger.get_instance()
        self._parser_factory   = parser_factory
        self._pub_factory      = publisher_factory
        self._col_factory      = collector_factory
        self._enr_factory      = enricher_factory

    def build(
        self,
        services:   list[str],
        publishers: list[str],
        collectors: list[str],
        enrichers:  list[str],
    ) -> Pipeline:
        """
        Iterate over each config list, delegate creation to the matching factory,
        and return a fully populated Pipeline.
        """
        pipeline = Pipeline()

        for name in services:
            try:
                pipeline.add_parser(name, self._parser_factory.create_log_parser(name))
                self._L.debug("Director: added parser '%s'", name)
            except Exception as exc:
                self._L.warning("Director: skipping parser '%s' -- %s", name, exc)

        for name in publishers:
            try:
                pipeline.add_publisher(self._pub_factory.create_publisher(name))
                self._L.debug("Director: added publisher '%s'", name)
            except Exception as exc:
                self._L.warning("Director: skipping publisher '%s' -- %s", name, exc)

        for name in collectors:
            try:
                pipeline.add_collector(self._col_factory.create_log_collector(name))
                self._L.debug("Director: added collector '%s'", name)
            except Exception as exc:
                self._L.warning("Director: skipping collector '%s' -- %s", name, exc)

        for name in enrichers:
            try:
                pipeline.add_enricher(self._enr_factory.create_log_enricher(name))
                self._L.debug("Director: added enricher '%s'", name)
            except Exception as exc:
                self._L.warning("Director: skipping enricher '%s' -- %s", name, exc)

        self._L.info(
            "Director: pipeline ready -- parsers=%d collectors=%d enrichers=%d publishers=%d",
            len(pipeline.parsers),
            len(pipeline.collectors),
            len(pipeline.enrichers),
            len(pipeline.publishers),
        )
        return pipeline