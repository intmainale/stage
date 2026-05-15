"""
Config: Settings
Singleton config reader.  Loads a YAML file (config/settings.yaml) if PyYAML
is available, otherwise falls back to environment variables with dotted-key
conventions (e.g. MQTT_HOST for mqtt.host).
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Optional

try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


class Settings:
    """Singleton settings store."""

    _instance: Optional[Settings] = None
    _lock = threading.Lock()

    def __init__(self, config_path: str = "config/settings.yaml") -> None:
        self._data: dict[str, Any] = {}
        path = Path(config_path)
        if _YAML_AVAILABLE and path.exists():
            with path.open("r") as fh:
                self._data = yaml.safe_load(fh) or {}
        # Environment variables act as overrides: MQTT_HOST → mqtt.host
        for key, val in os.environ.items():
            dotted = key.lower().replace("_", ".", 1)
            self._data[dotted] = val

    @classmethod
    def get_instance(cls, config_path: str = "config/settings.yaml") -> "Settings":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(config_path)
        return cls._instance

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a config value by dotted key (e.g. 'mqtt.host')."""
        parts = key.split(".")
        node: Any = self._data
        for part in parts:
            if not isinstance(node, dict):
                return default
            node = node.get(part)
            if node is None:
                return default
        return node if node is not None else default