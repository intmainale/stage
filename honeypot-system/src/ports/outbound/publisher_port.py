"""
Port: Publisher
Outbound port — defines the contract every publisher adapter must satisfy.
"""

from abc import ABC, abstractmethod

from src.domain.models.event import Event
from src.infrastructure.logger import Logger


class Publisher(ABC):
    """
    <<interface>>
    Publishes a processed Event to an external destination (MQTT broker, etc.).
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    def close(self) -> None:
        """Release owned resources; default no-op for publishers."""
        pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @abstractmethod
    def publish(self, entry: Event) -> None:
        """
        Publish *entry* to the target system.

        Raises PublishError on failure.
        """
        pass