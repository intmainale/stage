import pytest

from src.factories.concrete_factories import (
    ConcreteLogParserFactory,
    ConcretePublisherFactory,
    ConcreteLogCollectorFactory,
    ConcreteLogEnricherFactory,
)
from src.domain.exceptions.domain_exceptions import ConfigurationError


def test_concrete_log_parser_factory_creates_known_parser():
    parser = ConcreteLogParserFactory().create_log_parser("apache", "/tmp/log")
    assert parser is not None


def test_concrete_log_collector_factory_creates_known_collector():
    collector = ConcreteLogCollectorFactory().create_log_collector("apache", "/tmp/log")
    assert collector is not None


def test_concrete_log_enricher_factory_creates_known_enricher_with_patched_init(mocker):
    mocker.patch("src.factories.concrete_factories.VirusTotalEnricherAdapter.__init__", return_value=None)
    enricher = ConcreteLogEnricherFactory().create_log_enricher("virustotal")
    assert enricher is not None


def test_concrete_publisher_factory_creates_debug_publisher_with_patched_init(mocker):
    mocker.patch("src.factories.concrete_factories.DebugFilePublisherAdapter.__init__", return_value=None)
    publisher = ConcretePublisherFactory().create_publisher("debug")
    assert publisher is not None


def test_concrete_factories_raise_on_unknown_type():
    with pytest.raises(ConfigurationError):
        ConcreteLogParserFactory().create_log_parser("unknown", "/tmp")
    with pytest.raises(ConfigurationError):
        ConcreteLogCollectorFactory().create_log_collector("unknown", "/tmp")
    with pytest.raises(ConfigurationError):
        ConcretePublisherFactory().create_publisher("unknown")
    with pytest.raises(ConfigurationError):
        ConcreteLogEnricherFactory().create_log_enricher("unknown")