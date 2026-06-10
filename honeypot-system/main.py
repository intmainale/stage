"""
Composition Root — main.py
Wires the full object graph and starts the application.
"""
import logging
from config.settings import Settings

from src.application.application import Application

LOG_LEVELS = {
    "1": logging.DEBUG,
    "2": logging.INFO,
    "3": logging.WARNING,
    "4": logging.ERROR,
    "5": logging.CRITICAL,
}

def main() -> None:
    cfg = Settings.get_instance()

    collectors = {
        name: cfg.get(f"collectors.{name}", {})
        for name in cfg.get("pipeline.collectors", [])
    }
    
    services   = cfg.get("pipeline.services", ["bash", "auditd"])
    publishers = cfg.get("pipeline.publishers", ["mqtt"])
    enrichers  = cfg.get("pipeline.enrichers",  [])


    print("""
    Select logging level:
    1 - DEBUG
    2 - INFO
    3 - WARNING
    4 - ERROR
    5 - CRITICAL
    """)

    choice = input("Enter choice (1-5) [default: 2]: ").strip()

    logging_level = LOG_LEVELS.get(choice, logging.INFO)

    
    app = Application(
        collectors       = collectors,
        services         = services,
        enrichment_tools = enrichers,
        publishers       = publishers,
        logging_level    = logging_level
    )

    app.run()

if __name__ == "__main__":
    main()