from src.application.pipeline_builder import PipelineBuilder
from src.application.pipeline import Pipeline
from src.factories.concrete_factories import (
    ConcreteLogParserFactory,
    ConcretePublisherFactory,
    ConcreteLogCollectorFactory,
    ConcreteLogEnricherFactory,
)


class StubCollectorFactory:
    def create_log_collector(self, name, path):
        if name == "bad":
            raise ValueError("bad collector")
        return f"collector:{name}:{path}"


class StubParserFactory:
    def create_log_parser(self, name, path):
        if name == "bad":
            raise ValueError("bad parser")
        return f"parser:{name}:{path}"


class StubEnricherFactory:
    def create_log_enricher(self, name):
        if name == "bad":
            raise ValueError("bad enricher")
        return f"enricher:{name}"


class StubPublisherFactory:
    def create_publisher(self, name):
        if name == "bad":
            raise ValueError("bad publisher")
        return f"publisher:{name}"


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


def test_pipeline_builder_skips_factories_that_raise():
    builder = PipelineBuilder(
        parser_factory=StubParserFactory(),
        publisher_factory=StubPublisherFactory(),
        collector_factory=StubCollectorFactory(),
        enricher_factory=StubEnricherFactory(),
    )

    pipeline = builder.build(
        collectors={
            "good": {"path": ["/tmp/good.log"]},
            "bad": {"path": ["/tmp/bad.log"]},
        },
        services={
            "good": {"path": ["/tmp/good.log"]},
            "bad": {"path": ["/tmp/bad.log"]},
        },
        enrichers=["good", "bad"],
        publishers=["good", "bad"],
    )

    assert pipeline.collectors == ["collector:good:/tmp/good.log"]
    assert pipeline.parsers == {"good": "parser:good:/tmp/good.log"}
    assert pipeline.enrichers == ["enricher:good"]
    assert pipeline.publishers == ["publisher:good"]
