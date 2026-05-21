"""
Config: Settings
Singleton config reader.  Loads a YAML file (config/settings.yaml) if PyYAML
is available, otherwise falls back to environment variables with dotted-key
conventions (e.g. MQTT_HOST for mqtt.host).
"""
from __future__ import annotations

from glob import glob
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

        self._expand_paths()
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
    
    def _expand_paths(self) -> None:
        collectors = self._data.get("collectors", {})
        bash_collector = collectors.get("bash", {})

        if not bash_collector:
            return

        configured_paths = bash_collector.get("path", [])

        pattern = "/home/*/.bash_history"

        discovered = []
        for path in glob(pattern):
            p = Path(path)

            if p.exists() and p.is_file():
                discovered.append(str(p))

        bash_collector["path"] = list(dict.fromkeys(configured_paths + discovered))