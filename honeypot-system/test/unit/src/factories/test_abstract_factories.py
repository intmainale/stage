from src.factories.abstract_factories import (
    LogParserFactory,
    PublisherFactory,
    LogCollectorFactory,
    LogEnricherFactory,
)


class DummyParserFactory(LogParserFactory):
    def create_log_parser(self, parser_type: str):
        super().create_log_parser(parser_type)
        return parser_type


class DummyPublisherFactory(PublisherFactory):
    def create_publisher(self, publisher_type: str):
        super().create_publisher(publisher_type)
        return publisher_type


class DummyCollectorFactory(LogCollectorFactory):
    def create_log_collector(self, collector_type: str, path: str):
        super().create_log_collector(collector_type, path)
        return collector_type


class DummyEnricherFactory(LogEnricherFactory):
    def create_log_enricher(self, enricher_type: str):
        super().create_log_enricher(enricher_type)
        return enricher_type


def test_abstract_factory_base_methods_are_callable():
    assert DummyParserFactory().create_log_parser("bash") == "bash"
    assert DummyPublisherFactory().create_publisher("mqtt") == "mqtt"
    assert DummyCollectorFactory().create_log_collector("apache", "/tmp/log") == "apache"
    assert DummyEnricherFactory().create_log_enricher("shodan") == "shodan"
