"""
Port: LogCollector
Outbound port — defines the contract every log-collector adapter must satisfy.
"""

from abc import ABC, abstractmethod
import threading
from typing import Iterator

from src.infrastructure.logger import Logger


class LogCollector(ABC):
    """
    <<interface>>
    Yields raw log lines from a system source (journald, auditd, bash history, …).
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def collect(self, stop_event: threading.Event) -> Iterator[str]:
        """
        Yield raw log lines one at a time.

        Raises CollectionError on unrecoverable read failures.
        """
        pass
