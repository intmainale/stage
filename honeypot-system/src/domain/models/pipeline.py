"""
A plain container that holds the assembled adapters for one processing pipeline.
No builder pattern, no named setters per adapter type — just typed lists and a dict.
Adding a new adapter type requires zero changes here.
"""

from dataclasses import field, dataclass

from src.ports.outbound.log_parser_port import LogParser
from src.ports.outbound.publisher_port import Publisher
from src.ports.outbound.log_collector_port import LogCollector
from src.ports.outbound.log_enricher_port import LogEnricher

@dataclass
class Pipeline:
    parsers:    dict[str, LogParser] = field(default_factory=dict)
    collectors: list[LogCollector]   = field(default_factory=list)
    enrichers:  list[LogEnricher]    = field(default_factory=list)
    publishers: list[Publisher]      = field(default_factory=list)

    def add_parser(self, name: str, parser: LogParser) -> None:
        self.parsers[name] = parser

    def add_collector(self, collector: LogCollector) -> None:
        self.collectors.append(collector)

    def add_enricher(self, enricher: LogEnricher) -> None:
        self.enrichers.append(enricher)

    def add_publisher(self, publisher: Publisher) -> None:
        self.publishers.append(publisher)

    def is_empty(self) -> bool:
        return not any([self.parsers, self.collectors, self.enrichers, self.publishers])