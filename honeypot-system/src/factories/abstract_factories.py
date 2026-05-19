"""
Abstract Factories
Provides one factory per adapter family.  Concrete sub-factories are registered
via factory_registry.py so the rest of the codebase never imports adapters directly.
"""

from abc import ABC, abstractmethod

from src.ports.outbound.log_parser_port import LogParser
from src.ports.outbound.publisher_port import Publisher
from src.ports.outbound.log_collector_port import LogCollector
from src.ports.outbound.log_enricher_port import LogEnricher
from src.infrastructure.logger import Logger


# ──────────────────────────────────────────────────────────────────────────────
#  LogParserFactory
# ──────────────────────────────────────────────────────────────────────────────

class LogParserFactory(ABC):
    """
    <<abstract>>
    Returns a LogParser for a named service/protocol.
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def create_log_parser(self, parser_type: str) -> LogParser:
        """Instantiate and return the requested LogParser."""
        pass


# ──────────────────────────────────────────────────────────────────────────────
#  PublisherFactory
# ──────────────────────────────────────────────────────────────────────────────

class PublisherFactory(ABC):
    """
    <<abstract>>
    Returns a Publisher for the configured destination.
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def create_publisher(self, publisher_type: str) -> Publisher:
        """Instantiate and return the requested Publisher."""
        pass


# ──────────────────────────────────────────────────────────────────────────────
#  LogCollectorFactory
# ──────────────────────────────────────────────────────────────────────────────

class LogCollectorFactory(ABC):
    """
    <<abstract>>
    Returns a LogCollector for the configured source.
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def create_log_collector(self, collector_type: str) -> LogCollector:
        """Instantiate and return the requested LogCollector."""
        pass


# ──────────────────────────────────────────────────────────────────────────────
#  LogEnricherFactory
# ──────────────────────────────────────────────────────────────────────────────

class LogEnricherFactory(ABC):
    """
    <<abstract>>
    Returns a LogEnricher for the configured threat-intel service.
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def create_log_enricher(self, enricher_type: str) -> LogEnricher:
        """Instantiate and return the requested LogEnricher."""
        pass