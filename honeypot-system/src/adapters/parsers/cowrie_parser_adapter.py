"""Adapter: CowrieParserAdapter — parses security-relevant Cowrie JSON events."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.domain.exceptions.domain_exceptions import (
    ParseError,
    TimestampError,
)
from src.domain.models.event import CowrieEvent
from src.ports.outbound.log_parser_port import LogParser


OUTPUT_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


# ──────────────────────────────────────────────────────────────────────────────
# Command Classification
# ──────────────────────────────────────────────────────────────────────────────

_DOWNLOAD = {
    "wget ",
    "curl ",
    "fetch ",
    "tftp ",
    "ftpget ",
    "ftp ",
    "busybox wget",
    "busybox tftp",
}

_SHELL = {
    "/bin/sh",
    "/bin/bash",
    "sh -i",
    "bash -i",
}

_PRIVESC = {
    "sudo ",
    "su ",
    "chmod +s",
    "setcap ",
}

_PERSIST = {
    "crontab",
    "/etc/cron",
    ".ssh/authorized_keys",
    "systemctl enable",
    "@reboot",
}

_RECON = {
    "whoami",
    "id ",
    "uname",
    "hostname",
    "ifconfig",
    "ip a",
    "netstat",
    "ss ",
    "ps aux",
    "history",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "lscpu",
    "free -m",
}

_NETWORK = {
    "ssh ",
    "scp ",
    "nc ",
    "ncat ",
    "telnet ",
}


# ──────────────────────────────────────────────────────────────────────────────
# File Classification
# ──────────────────────────────────────────────────────────────────────────────

_EXECUTABLE_EXTENSIONS = {
    ".sh",
    ".bash",
    ".py",
    ".pl",
    ".php",
    ".exe",
    ".dll",
    ".bin",
    ".elf",
}

_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".rar",
    ".7z",
}

_SCRIPT_KEYWORDS = {
    "payload",
    "dropper",
    "miner",
    "bot",
    "install",
    "setup",
}

_MALWARE_NAMES = {
    "mirai",
    "arm",
    "arm7",
    "armv7",
    "mips",
    "mipsel",
    "x86",
    "dropper",
    "payload",
    "bot",
}


class CowrieParserAdapter(LogParser):
    """
    Parses security-relevant Cowrie events.

    Supported:
        cowrie.login.success
        cowrie.login.failed
        cowrie.session.file_upload
        cowrie.session.file_download
        cowrie.command.input
        cowrie.command.failed
    """

    SUPPORTED_EVENTS = {
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.session.file_upload",
        "cowrie.session.file_download",
        "cowrie.command.input",
        "cowrie.command.failed",
    }

    def parse(
        self,
        raw_line: str,
        path: str,
    ) -> Optional[CowrieEvent]:

        raw_line = raw_line.strip()

        if not raw_line:
            return None

        try:
            event = json.loads(raw_line)

        except json.JSONDecodeError as exc:
            raise ParseError(
                "CowrieParserAdapter: invalid JSON"
            ) from exc

        eventid = event.get("eventid")

        if eventid not in self.SUPPORTED_EVENTS:
            return None

        timestamp = self._parse_timestamp(
            event.get("timestamp")
        )

        action = self.classify_event(
            eventid,
            event,
        )

        severity_score = self.classify_severity(
            action
        )

        cowrie_event = CowrieEvent(
            timestamp=timestamp,
            source="cowrie",

            ip=event.get("src_ip"),
            session=event.get("session"),

            operation=self.classify_operation(
                eventid
            ),

            action=action,

            success=self.extract_success(
                eventid
            ),

            severity_score=severity_score,

            username=event.get("username"),

            command=event.get("input"),

            url=event.get("url"),
            filename=event.get("filename"),

            raw=raw_line,
        )

        self._L.debug(
            "CowrieParserAdapter: parsed event=%s",
            cowrie_event,
        )

        return cowrie_event

    # ──────────────────────────────────────────────────────────────────────
    # Timestamp
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_timestamp(
        ts: str | None,
    ) -> str:

        if not ts:
            raise TimestampError(
                "CowrieParserAdapter: missing timestamp"
            )

        try:
            dt = datetime.fromisoformat(
                ts.replace("Z", "+00:00")
            )

            return (
                dt.astimezone(timezone.utc)
                .strftime(OUTPUT_TS_FMT)
            )

        except Exception as exc:
            raise TimestampError(
                "CowrieParserAdapter: invalid timestamp"
            ) from exc

    # ──────────────────────────────────────────────────────────────────────
    # Operation Classification
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def classify_operation(
        eventid: str,
    ) -> str:

        if eventid.startswith("cowrie.login."):
            return "authentication"

        if eventid.startswith("cowrie.command."):
            return "command_execution"

        if eventid.startswith("cowrie.session.file_"):
            return "file_transfer"

        return "unknown"

    # ──────────────────────────────────────────────────────────────────────
    # Event Classification
    # ──────────────────────────────────────────────────────────────────────

    @classmethod
    def classify_event(
        cls,
        eventid: str,
        event: dict,
    ) -> str:

        if eventid == "cowrie.login.success":
            return "login_success"

        if eventid == "cowrie.login.failed":
            return "login_failed"

        if eventid == "cowrie.session.file_upload":
            return cls.classify_file_event(
                filename=event.get("filename"),
                url=None,
                upload=True,
            )

        if eventid == "cowrie.session.file_download":
            return cls.classify_file_event(
                filename=None,
                url=event.get("url"),
                upload=False,
            )

        if eventid == "cowrie.command.failed":
            return "command_failed"

        if eventid == "cowrie.command.input":
            return cls.classify_command(
                event.get("input")
            )

        return "unknown"

    @staticmethod
    def classify_command(
        cmd: str | None,
    ) -> str:

        cmd = (cmd or "").lower()

        if any(x in cmd for x in _DOWNLOAD):
            return "download"

        if any(x in cmd for x in _SHELL):
            return "shell"

        if any(x in cmd for x in _PRIVESC):
            return "privilege_escalation"

        if any(x in cmd for x in _PERSIST):
            return "persistence"

        if any(x in cmd for x in _RECON):
            return "recon"

        if any(x in cmd for x in _NETWORK):
            return "network"

        return "command"

    @staticmethod
    def classify_file_event(
        filename: str | None,
        url: str | None,
        upload: bool,
    ) -> str:

        target = (filename or url or "").lower()

        if any(
            name in target
            for name in _MALWARE_NAMES
        ):
            return (
                "malware_upload"
                if upload
                else "malware_download"
            )

        suffix = Path(target).suffix

        if suffix in _EXECUTABLE_EXTENSIONS:
            return (
                "malware_upload"
                if upload
                else "malware_download"
            )

        if suffix in _ARCHIVE_EXTENSIONS:
            return (
                "archive_upload"
                if upload
                else "archive_download"
            )

        if any(
            keyword in target
            for keyword in _SCRIPT_KEYWORDS
        ):
            return (
                "suspicious_upload"
                if upload
                else "suspicious_download"
            )

        return (
            "file_upload"
            if upload
            else "file_download"
        )

    # ──────────────────────────────────────────────────────────────────────
    # Success
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def extract_success(
        eventid: str,
    ) -> bool | None:

        if eventid == "cowrie.login.success":
            return True

        if eventid == "cowrie.login.failed":
            return False

        return None

    # ──────────────────────────────────────────────────────────────────────
    # Severity
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def classify_severity(
        action: str,
    ) -> int:

        severity_mapping = {
            "malware_upload": 4,
            "malware_download": 4,
            "download": 4,
            "privilege_escalation": 4,
            "persistence": 4,

            "archive_upload": 3,
            "archive_download": 3,
            "suspicious_upload": 3,
            "suspicious_download": 3,
            "shell": 3,
            "network": 3,
            "login_success": 3,

            "login_failed": 2,
            "recon": 2,
            "file_upload": 2,
            "file_download": 2,

            "command": 1,
            "command_failed": 1,
        }

        return severity_mapping.get(action, 1)