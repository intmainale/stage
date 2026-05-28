from dataclasses import dataclass, field
from typing import Any


# ── Enrichments ────────────────────────────────────────────────────────────────

@dataclass
class VirusTotalInfo:
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    reputation: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class ShodanInfo:
    asn: str | None = None
    os: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    open_ports: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class AbuseIPDBInfo:
    abuse_confidence_score: int | None = None

    country: str | None = None
    region: str | None = None
    city: str | None = None

    latitude: float | None = None
    longitude: float | None = None

    isp: str | None = None
    usage_type: str | None = None
    total_reports: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class EnrichmentBundle:
    virustotal: VirusTotalInfo | None = None
    shodan: ShodanInfo | None = None
    abuseipdb: AbuseIPDBInfo | None = None


# ── Main Events ────────────────────────────────────────────────────────────────

@dataclass
class Event:
    source: str = "generic"
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
        }


@dataclass
class EnrichableEvent(Event):
    ip: str | None = None
    enrichments: EnrichmentBundle = field(
        default_factory=EnrichmentBundle
    )

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()

        data["ip"] = self.ip

        if self.enrichments.virustotal:
            data.update(self.enrichments.virustotal.to_dict())

        if self.enrichments.shodan:
            data.update(self.enrichments.shodan.to_dict())

        if self.enrichments.abuseipdb:
            data.update(self.enrichments.abuseipdb.to_dict())

        return data


@dataclass
class AuditdExecEvent(Event):
    source: str = "auditd"

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
        data = super().to_dict()

        data.update({
            "event_id": self.event_id,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "exe": self.exe,
            "comm": self.comm,
            "success": self.success,
            "syscall": self.syscall,
            "raw": self.raw,
        })

        return data


@dataclass
class BashEvent(Event):
    source: str = "bash"

    cmd: str | None = None
    action: str | None = None
    severity_score: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()

        data.update({
            "cmd": self.cmd,
            "action": self.action,
            "severity_score": self.severity_score,
        })

        return data


@dataclass
class ApacheEvent(EnrichableEvent):
    source: str = "apache"

    user: str | None = None
    action: str | None = None
    success: bool | None = None
    severity_score: int | None = None

    method: str | None = None
    operation: str | None = None
    path: str | None = None
    status: int | None = None

    message: str | None = None
    size: int | None = None
    raw: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()

        data.update({
            "user": self.user,
            "action": self.action,
            "success": self.success,
            "severity_score": self.severity_score,
            "method": self.method,
            "operation": self.operation,
            "path": self.path,
            "status": self.status,
            "message": self.message,
            "size": self.size,
            "raw": self.raw,
        })

        return data


@dataclass
class FTPEvent(EnrichableEvent):
    source: str = "ftp-extended"

    username: str | None = None
    command: str | None = None
    operation: str | None = None
    action: str | None = None

    success: bool | None = None
    status: str | None = None
    severity_score: int | None = None

    file_path: str | None = None
    bytes_transferred: int | None = None
    access_mode: str | None = None

    pid: int | None = None
    message: str | None = None
    raw: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()

        data.update({
            "username": self.username,
            "command": self.command,
            "operation": self.operation,
            "action": self.action,
            "success": self.success,
            "status": self.status,
            "severity_score": self.severity_score,
            "file_path": self.file_path,
            "bytes_transferred": self.bytes_transferred,
            "access_mode": self.access_mode,
            "pid": self.pid,
            "message": self.message,
            "raw": self.raw,
        })

        return data