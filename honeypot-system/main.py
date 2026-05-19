"""
Composition Root — main.py
Wires the full object graph and starts the application.
"""
from __future__ import annotations

import signal
import sys
import threading

from config.settings import Settings

from src.application.application import Application


def main() -> None:
    cfg = Settings.get_instance()

    services   = cfg.get("pipeline.services",   ["bash", "apache", ])
    collectors = cfg.get("pipeline.collectors", ["bash"])
    publishers = cfg.get("pipeline.publishers", ["mqtt"])
    enrichers  = cfg.get("pipeline.enrichers",  [])

    app = Application(
        services         = services,
        publishers       = publishers,
        collectors       = collectors,
        enrichment_tools = enrichers,
    )

    def _shutdown(signum, frame):
        app.stop_pipeline()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    app.build_pipeline()
    app.start_pipeline()

    for t in threading.enumerate():
        if t is not threading.main_thread():
            t.join()


if __name__ == "__main__":
    main()