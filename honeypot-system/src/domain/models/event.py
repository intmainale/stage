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

    def to_dict(self):
        return {
            "geolocation": self.geolocation.__dict__ if self.geolocation else None,
            "virustotal": self.virustotal.__dict__ if self.virustotal else None,
            "shodan": self.shodan.__dict__ if self.shodan else None,
            "abuseipdb": self.abuseipdb.__dict__ if self.abuseipdb else None,
        }

# ── Main Events ─────────────────────────────────────────────────────────────────────

@dataclass
class EnrichableEvent:
    timestamp: datetime
    ip: str | None = None
    enrichments: EnrichmentBundle = field(default_factory=EnrichmentBundle)

@dataclass
class AuditdExecEvent:
    source: str = "auditd"
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "exe": self.exe,
            "comm": self.comm,
            "success": self.success,
            "syscall": self.syscall,
            "raw": self.raw,
        }

@dataclass
class BashEvent:
    source: str = "bash"
    cmd: str | None = None
    action: str | None = None
    severity_score: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_line": self.command_line,
            "action": self.action,
            "severity_score": self.severity_score,
        }

@dataclass
class ApacheEvent(EnrichableEvent):
    timestamp: datetime
    source: str = "apache"
    ip: str | None = None
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    size: int | None = None
    enrichments: EnrichmentBundle = field(default_factory=EnrichmentBundle)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "user": self.user,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "size": self.size,
            "enrichments": self.enrichments.to_dict() if self.enrichments else None,
        }