"""
Concrete Factories
These are the only place in the codebase that import concrete adapter classes.
All other layers depend only on ports and abstract factories.
"""

from src.factories.abstract_factories import (
    LogParserFactory,
    PublisherFactory,
    LogCollectorFactory,
    LogEnricherFactory,
)
from src.ports.outbound.log_parser_port import LogParser
from src.ports.outbound.publisher_port import Publisher
from src.ports.outbound.log_collector_port import LogCollector
from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.exceptions.domain_exceptions import ConfigurationError

# ── parser adapters ──────────────────────────────────────────────────────────
from src.adapters.parsers.bash_parser_adapter import BashParserAdapter
#from src.adapters.parsers.ftp_parser_adapter import FTPParserAdapter
from src.adapters.parsers.apache_parser_adapter import ApacheParserAdapter
from src.adapters.parsers.auditd_parser_adapter import AuditdParserAdapter
#from src.adapters.parsers.cowrie_parser_adapter import CowrieParserAdapter
#from src.adapters.parsers.custom_service_parser_adapter import CustomServiceParserAdapter

# ── publisher adapters ───────────────────────────────────────────────────────
from src.adapters.publishers.mqtt_publisher_adapter import MQTTPublisherAdapter

# ── collector adapters ───────────────────────────────────────────────────────
from src.adapters.collectors.bash_log_collector_adapter import BashLogCollectorAdapter
from src.adapters.collectors.auditd_log_collector_adapter import AuditdLogCollectorAdapter
from src.adapters.collectors.apache_log_collector_adapter import ApacheLogCollectorAdapter
#from src.adapters.collectors.journald_log_collector_adapter import JournaldLogCollector

# ── enricher adapters ────────────────────────────────────────────────────────
from src.adapters.enrichers.virustotal_enricher_adapter import VirusTotalEnricherAdapter
from src.adapters.enrichers.abuseipdb_enricher_adapter import AbuseIPDBEnricherAdapter
from src.adapters.enrichers.shodan_enricher_adapter import ShodanEnricherAdapter


# ──────────────────────────────────────────────────────────────────────────────

class ConcreteLogParserFactory(LogParserFactory):
    _REGISTRY: dict[str, type[LogParser]] = {
        "bash":           BashParserAdapter,
        #"ftp":            FTPParserAdapter,
        "apache":         ApacheParserAdapter,
        #"cowrie":         CowrieParserAdapter,
        #"custom_service": CustomServiceParserAdapter,
        "auditd":         AuditdParserAdapter,
    }

    def create_log_parser(self, parser_type: str) -> LogParser:
        cls = self._REGISTRY.get(parser_type.lower())
        if cls is None:
            raise ConfigurationError(f"Unknown parser type: '{parser_type}'")
        self._L.debug("Creating parser: %s", parser_type)
        return cls()


class ConcretePublisherFactory(PublisherFactory):
    _REGISTRY: dict[str, type[Publisher]] = {
        "mqtt": MQTTPublisherAdapter,
    }

    def create_publisher(self, publisher_type: str) -> Publisher:
        cls = self._REGISTRY.get(publisher_type.lower())
        if cls is None:
            raise ConfigurationError(f"Unknown publisher type: '{publisher_type}'")
        self._L.debug("Creating publisher: %s", publisher_type)
        return cls()


class ConcreteLogCollectorFactory(LogCollectorFactory):
    _REGISTRY: dict[str, type[LogCollector]] = {
        "bash":    BashLogCollectorAdapter,
        "auditd":  AuditdLogCollectorAdapter,
        #"journald": JournaldLogCollectorAdapter,
        "apache":  ApacheLogCollectorAdapter,
    }

    def create_log_collector(self, collector_type: str) -> LogCollector:
        cls = self._REGISTRY.get(collector_type.lower())
        if cls is None:
            raise ConfigurationError(f"Unknown collector type: '{collector_type}'")
        self._L.debug("Creating collector: %s", collector_type)
        return cls()


class ConcreteLogEnricherFactory(LogEnricherFactory):
    _REGISTRY: dict[str, type[LogEnricher]] = {
        "virustotal": VirusTotalEnricherAdapter,
        "abuseipdb":  AbuseIPDBEnricherAdapter,
        "shodan":     ShodanEnricherAdapter,
    }

    def create_log_enricher(self, enricher_type: str) -> LogEnricher:
        cls = self._REGISTRY.get(enricher_type.lower())
        if cls is None:
            raise ConfigurationError(f"Unknown enricher type: '{enricher_type}'")
        self._L.debug("Creating enricher: %s", enricher_type)
        return cls()