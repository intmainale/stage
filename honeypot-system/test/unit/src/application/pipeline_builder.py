from src.application.pipeline_builder import PipelineBuilder
from src.application.pipeline import Pipeline
from src.factories.concrete_factories import (
    ConcreteLogParserFactory,
    ConcretePublisherFactory,
    ConcreteLogCollectorFactory,
    ConcreteLogEnricherFactory,
)


def test_pipeline_builder_creates_parser_and_collector_entries():
    builder = PipelineBuilder(
        parser_factory=ConcreteLogParserFactory(),
        publisher_factory=ConcretePublisherFactory(),
        collector_factory=ConcreteLogCollectorFactory(),
        enricher_factory=ConcreteLogEnricherFactory(),
    )

    pipeline = builder.build(
        collectors={"apache": {"path": ["/var/log/apache2/access.log"]}},
        services={"apache": {"path": ["/var/log/apache2/access.log"]}},
        enrichers=[],
        publishers=[],
    )

    assert isinstance(pipeline, Pipeline)
    assert "apache" in pipeline.parsers
    assert len(pipeline.collectors) == 1
    assert len(pipeline.enrichers) == 0
    assert len(pipeline.publishers) == 0
