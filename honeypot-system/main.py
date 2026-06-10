"""
Composition Root — main.py
Wires the full object graph and starts the application.
"""
import sys

from config.settings import Settings

from src.application.application import Application

def main() -> None:
    cfg = Settings.get_instance()

    collectors = {
        name: cfg.get(f"collectors.{name}", {})
        for name in cfg.get("pipeline.collectors", [])
    }
    
    services   = cfg.get("pipeline.services", ["bash", "auditd"])
    publishers = cfg.get("pipeline.publishers", ["mqtt"])
    enrichers  = cfg.get("pipeline.enrichers",  [])
    
    app = Application(
        collectors       = collectors,
        services         = services,
        enrichment_tools = enrichers,
        publishers       = publishers
    )

    exit_code = app.run()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()