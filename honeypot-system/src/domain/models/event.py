from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


# =========================================================
# SHARED ENTITIES
# =========================================================

@dataclass
class Actor:
    username: str | None = None
    uid: int | None = None
    groups: list[str] = field(default_factory=list)


@dataclass
class NetworkInfo:
    src_ip: str | None = None
    dst_ip: str | None = None

    src_port: int | None = None
    dst_port: int | None = None

    protocol: str | None = None


@dataclass
class ProcessInfo:
    pid: int | None = None
    ppid: int | None = None

    executable: str | None = None
    command_line: str | None = None


# =========================================================
# ENRICHMENTS
# =========================================================

@dataclass
class VirusTotalInfo:
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None

    reputation: int | None = None


@dataclass
class ShodanInfo:
    organization: str | None = None
    os: str | None = None

    open_ports: list[int] = field(default_factory=list)

    tags: list[str] = field(default_factory=list)


@dataclass
class AbuseIPDBInfo:
    score: int | None = None

    country: str | None = None
    isp: str | None = None
    usage_type: str | None = None

    total_reports: int | None = None


@dataclass
class GeoInfo:
    country: str | None = None
    region: str | None = None
    city: str | None = None

    latitude: float | None = None
    longitude: float | None = None


@dataclass
class EnrichmentBundle:
    geolocation: GeoInfo | None = None

    virustotal: VirusTotalInfo | None = None
    shodan: ShodanInfo | None = None
    abuseipdb: AbuseIPDBInfo | None = None


# =========================================================
# METRICS LAYER
# =========================================================

@dataclass
class EventMetrics:
    # Generic scoring
    risk_score: int = 0
    severity_score: int = 0

    # Security indicators
    is_malicious: bool = False
    is_suspicious: bool = False
    is_tor_exit_node: bool = False
    is_scanner: bool = False
    is_internal_ip: bool = False

    # Authentication
    success: bool | None = None

    # Networking / web
    bytes_sent: int | None = None
    bytes_received: int | None = None
    duration_ms: int | None = None

    # HTTP
    http_status_code: int | None = None

    # Threat intel extracted metrics
    abuse_score: int | None = None
    vt_malicious: int | None = None
    open_ports_count: int | None = None


# =========================================================
# MAIN EVENT
# =========================================================

@dataclass
class Event:
    # -----------------------------------------------------
    # IDENTIFICATION
    # -----------------------------------------------------

    event_id: str = field(default_factory=lambda: str(uuid4()))

    timestamp: datetime = field(default_factory=datetime.utcnow)

    # -----------------------------------------------------
    # LOW CARDINALITY TAGS (GOOD FOR INFLUX TAGS)
    # -----------------------------------------------------

    source: str = "unknown"          # auditd, journald, apache
    service: str = "unknown"         # ssh, ftp, apache
    category: str = "generic"        # auth, process, network
    event_type: str = "generic"      # login_failed, process_exec

    host: str | None = None

    severity: str | None = None       # low, medium, high, critical
    environment: str | None = None    # prod, dev, dmz

    # -----------------------------------------------------
    # SEMANTIC TAGS
    # -----------------------------------------------------

    tags: list[str] = field(default_factory=list)

    # -----------------------------------------------------
    # CORE EVENT CONTENT
    # -----------------------------------------------------

    message: str | None = None

    actor: Actor | None = None
    network: NetworkInfo | None = None
    process: ProcessInfo | None = None

    # -----------------------------------------------------
    # ENRICHMENTS
    # -----------------------------------------------------

    enrichments: EnrichmentBundle | None = None

    # -----------------------------------------------------
    # METRICS / ANALYTICS
    # -----------------------------------------------------

    metrics: EventMetrics = field(default_factory=EventMetrics)

    # -----------------------------------------------------
    # PIPELINE CONTEXT
    # -----------------------------------------------------

    metadata: dict[str, Any] = field(default_factory=dict)

    # -----------------------------------------------------
    # RAW EVENT
    # -----------------------------------------------------

    raw: str | None = None