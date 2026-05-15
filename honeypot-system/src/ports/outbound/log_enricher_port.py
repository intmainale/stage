"""
Port: LogEnricher
Outbound port — defines the contract every enricher adapter must satisfy.
"""

from abc import ABC, abstractmethod

from src.domain.models.event import Event
from src.infrastructure.logger import Logger


class LogEnricher(ABC):
    """
    <<interface>>
    Enriches a Event with threat-intelligence data (VirusTotal, Shodan, AbuseIPDB, …).
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def enrich(self, entry: Event) -> Event:
        """
        Attach extra data to *entry* and return it (mutates enrichments dict in-place).

        Raises EnrichmentError on failure.
        """
        pass