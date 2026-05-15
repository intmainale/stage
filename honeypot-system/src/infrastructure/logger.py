"""
Infrastructure: Logger  (Singleton)
A thread-safe singleton wrapper around Python's standard logging module.
"""
import logging
import threading
from typing import Optional


class Logger:
    """
    <<singleton>>
    Central logger accessible from any layer
    """

    _instance: Optional["Logger"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, name: str = "eurosystem", level: int = logging.DEBUG) -> None:
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
        self._logger.setLevel(level)

    # ------------------------------------------------------------------ #
    #  Singleton factory                                                   #
    # ------------------------------------------------------------------ #

    @classmethod
    def get_instance(cls, name: str = "eurosystem", level: int = logging.DEBUG) -> "Logger":
        """Return the global Logger instance, creating it if necessary."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(name, level)
        return cls._instance

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def debug(self, msg: str, *args, **kwargs) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._logger.error(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs) -> None:
        self._logger.exception(msg, *args, **kwargs)