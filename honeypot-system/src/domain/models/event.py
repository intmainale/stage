from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

# ── Enrichments ────────────────────────────────────────────────────────────────────

@dataclass
class VirusTotalInfo:
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None

    reputation: int | None = None


@dataclass
class ShodanInfo:
    asn: str | None = None
    os: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    
    open_ports: list[int] = field(default_factory=list)

    tags: list[str] = field(default_factory=list)


@dataclass
class AbuseIPDBInfo:
    abuse_confidence_score: int | None = None

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


# ── Main Events ─────────────────────────────────────────────────────────────────────

@dataclass
class AuditdExecEvent:
    timestamp: float | None = None
    event_id: int | None = None

    pid: int | None = None
    ppid: int | None = None
    uid: int | None = None

    exe: str | None = None
    comm: str | None = None

    success: bool | None = None

    syscall: str | None = None

    raw: str | None = None

@dataclass
class BashEvent:
    timestamp: datetime
    username: str | None = None
    uid: int | None = None
    groups: list[str] = field(default_factory=list)
    pid: int | None = None
    ppid: int | None = None

@dataclass
class ApacheEvent:
    timestamp: datetime
    ip: str | None = None
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    size: int | None = None
    enrichment: EnrichmentBundle | None = None