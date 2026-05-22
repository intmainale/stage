from src.application.pipeline import Pipeline
from src.ports.outbound.log_parser_port import LogParser
from src.ports.outbound.log_collector_port import LogCollector
from src.ports.outbound.log_enricher_port import LogEnricher
from src.ports.outbound.publisher_port import Publisher


class DummyParser(LogParser):
    def parse(self, raw_line: str):
        return raw_line


class DummyCollector(LogCollector):
    def collect(self):
        return iter(["line"])


class DummyEnricher(LogEnricher):
    def enrich(self, entry):
        return entry


class DummyPublisher(Publisher):
    def publish(self, entry):
        self.published = getattr(self, "published", [])
        self.published.append(entry)


def test_pipeline_is_empty_by_default():
    pipeline = Pipeline()
    assert pipeline.is_empty()


def test_pipeline_adds_components_and_reports_non_empty():
    parser = DummyParser()
    collector = DummyCollector()
    enricher = DummyEnricher()
    publisher = DummyPublisher()

    pipeline = Pipeline()
    pipeline.add_parser("test", parser)
    pipeline.add_collector(collector)
    pipeline.add_enricher(enricher)
    pipeline.add_publisher(publisher)

    assert not pipeline.is_empty()
    assert pipeline.parsers["test"] is parser
    assert collector in pipeline.collectors
    assert enricher in pipeline.enrichers
    assert publisher in pipeline.publishers
