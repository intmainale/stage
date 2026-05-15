"""
Port: LogParser
Outbound port — defines the contract every log-parser adapter must satisfy.
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.domain.models.event import Event
from src.infrastructure.logger import Logger


class LogParser(ABC):
    """
    <<interface>>
    Parses a raw log line into a structured Event.
    """

    def __init__(self) -> None:
        self._L: Logger = Logger.get_instance()

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[Event]:
        """
        Parse *raw_line* and return a Event, or None if the line is
        not recognised / should be skipped.

        Raises ParseError on malformed input that should halt processing.
        """
        pass