"""
Config: Settings
Singleton config reader. Loads a YAML file (config/settings.yaml).
"""

from __future__ import annotations

import threading
from glob import glob
from pathlib import Path
from typing import Any, Optional

import yaml

from src.domain.exceptions.domain_exceptions import ConfigurationError


class Settings:
    """Singleton settings store."""

    _instance: Optional["Settings"] = None
    _lock = threading.Lock()

    def __init__(self, config_path: str = "config/settings.yaml") -> None:
        self._data: dict[str, Any] = {}
        path = Path(config_path)

        if not path.exists():
            raise ConfigurationError(f"Settings: config file not found: {config_path}")

        try:
            with path.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh)

        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Settings: invalid YAML format") from exc
        except OSError as exc:
            raise ConfigurationError(f"Settings: cannot read config file") from exc

        if loaded is None:
            loaded = {}

        if not isinstance(loaded, dict):
            raise ConfigurationError("Settings: root YAML must be a dictionary")

        self._data = loaded

        self._expand_paths()

    @classmethod
    def get_instance(cls, config_path: str = "config/settings.yaml") -> "Settings":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(config_path)
        return cls._instance

    def get(self, key: str, default: Any = None) -> Any:
        parts = key.split(".")
        node: Any = self._data

        for part in parts:
            if not isinstance(node, dict):
                return default
            node = node.get(part)
            if node is None:
                return default

        return node

    def _expand_paths(self) -> None:
        collectors = self._data.get("collectors")

        if not isinstance(collectors, dict):
            raise ConfigurationError("Settings: collectors must be a dict")

        bash_collector = collectors.get("bash")

        if not isinstance(bash_collector, dict):
            raise ConfigurationError("Settings: bash collector must be a dict")

        configured_paths = bash_collector.get("path", [])

        if not isinstance(configured_paths, list):
            raise ConfigurationError("Settings: bash collector 'path' must be a list")

        pattern = "/home/*/.bash_history"

        discovered = []
        for path in glob(pattern):
            p = Path(path)
            if p.exists() and p.is_file():
                discovered.append(str(p))

        bash_collector["path"] = list(dict.fromkeys(configured_paths + discovered))