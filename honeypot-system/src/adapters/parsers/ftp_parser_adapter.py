"""Adapter: FTPParserAdapter - parses FTP xferlog and extended log lines."""

from __future__ import annotations

from pathlib import Path
import re
import shlex
from datetime import datetime, timezone
from typing import Optional

from src.ports.outbound.log_parser_port import LogParser
from src.domain.models.event import FTPEvent
from src.domain.exceptions.domain_exceptions import ParseError


XFERLOG_TS_FMT = "%a %b %d %H:%M:%S %Y"
EXTENDED_TS_FMT = "%a %b %d %H:%M:%S %Y"

EXTENDED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
    r"(?:\s+\[pid\s+(?P<pid>\d+)\])?"
    r"(?:\s+\[(?P<user>[^\]]+)\])?"
    r"\s+(?P<status>OK|FAIL|FTP command|CONNECT|DISCONNECT)"
    r"(?:\s+(?P<operation>[A-Z_]+))?:\s+(?P<message>.*)$"
)

CLIENT_RE = re.compile(r'Client\s+"(?P<ip>[^"]+)"')
QUOTED_RE = re.compile(r'"([^"]*)"')
BYTES_RE = re.compile(r"(?P<bytes>\d+)\s+bytes\b")
COMMAND_RE = re.compile(r'"(?P<command>[A-Z]{3,4})(?:\s+(?P<argument>.*))?"')

SUSPICIOUS_PATH_PATTERNS = {
    "../",
    "..%2f",
    "%2e%2e",
    "/etc/passwd",
    "/etc/shadow",
    ".ssh/",
    "authorized_keys",
    ".php",
    ".jsp",
    ".asp",
    ".aspx",
    ".sh",
    ".elf",
    ".bin",
}

WRITE_COMMANDS = {"STOR", "STOU", "APPE", "MKD", "RMD", "DELE", "RNFR", "RNTO", "SITE", "CHMOD"}
READ_COMMANDS = {"RETR", "LIST", "NLST", "MLSD", "SIZE", "MDTM", "PWD", "CWD"}
AUTH_COMMANDS = {"USER", "PASS", "ACCT", "AUTH"}


class FTPParserAdapter(LogParser):
    """Parses FTP xferlog and common extended FTP daemon logs."""

    DEFAULT_PATH = "/var/log/vsftpd.log"

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = Path(path) if path else Path(self.DEFAULT_PATH)

    def parse(self, raw_line: str) -> Optional[FTPEvent]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        event = self._parse_xferlog(raw_line)
        if event is None:
            event = self._parse_extended(raw_line)

        return event

    def _parse_xferlog(self, raw_line: str) -> Optional[FTPEvent]:
        try:
            parts = shlex.split(raw_line)
        except ValueError as exc:
            raise ParseError(f"FTPParserAdapter: malformed xferlog quoting: {exc}") from exc

        if len(parts) < 17:
            return None

        try:
            timestamp = datetime.strptime(" ".join(parts[:5]), XFERLOG_TS_FMT).replace(tzinfo=timezone.utc)
            bytes_transferred = int(parts[7])
        except ValueError:
            return None

        remote_host = parts[6]
        file_path = parts[8]
        direction_code = parts[11]
        access_mode = parts[12]
        username = parts[13]
        completion_status = parts[17] if len(parts) > 17 else None

        operation = self.classify_operation(direction_code, None)
        success = completion_status == "c"
        action = self.classify_event(
            operation=operation,
            command=None,
            success=success,
            username=username,
            file_path=file_path,
            access_mode=access_mode,
        )

        return FTPEvent(
            timestamp=timestamp,
            source="ftp-xferlog",
            ip=remote_host,
            username=username,
            operation=operation,
            action=action,
            success=success,
            status=completion_status,
            severity_score=self.classify_severity(action),
            file_path=file_path,
            bytes_transferred=bytes_transferred,
            access_mode=access_mode,
            raw=raw_line,
        )

    def _parse_extended(self, raw_line: str) -> Optional[FTPEvent]:
        match = EXTENDED_RE.match(raw_line)
        if not match:
            return None

        try:
            timestamp = datetime.strptime(match.group("ts"), EXTENDED_TS_FMT).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ParseError(f"FTPParserAdapter: bad extended timestamp: {exc}") from exc

        status = match.group("status")
        operation = match.group("operation") or status
        message = match.group("message")
        username = self._empty_to_none(match.group("user"))
        pid = int(match.group("pid")) if match.group("pid") else None

        ip_match = CLIENT_RE.search(message)
        quoted = QUOTED_RE.findall(message)
        bytes_match = BYTES_RE.search(message)

        command = None
        file_path = None
        if status == "FTP command":
            command_match = COMMAND_RE.search(message)
            if command_match:
                command = command_match.group("command")
                file_path = self._empty_to_none(command_match.group("argument"))
        elif len(quoted) > 1:
            file_path = quoted[1]

        if operation in {"LOGIN", "CONNECT", "DISCONNECT"}:
            file_path = None

        success = self.classify_success(status, operation)
        normalized_operation = self.classify_operation(None, command or operation)
        action = self.classify_event(
            operation=normalized_operation,
            command=command,
            success=success,
            username=username,
            file_path=file_path,
            access_mode=None,
        )

        return FTPEvent(
            timestamp=timestamp,
            source="ftp-extended",
            ip=ip_match.group("ip") if ip_match else None,
            username=username,
            command=command,
            operation=normalized_operation,
            action=action,
            success=success,
            status=status,
            severity_score=self.classify_severity(action),
            file_path=file_path,
            bytes_transferred=int(bytes_match.group("bytes")) if bytes_match else None,
            pid=pid,
            message=message,
            raw=raw_line,
        )

    @staticmethod
    def classify_operation(direction: str | None, command_or_operation: str | None) -> str:
        value = (command_or_operation or "").upper()
        if direction == "i" or value in {"UPLOAD", "STOR", "STOU", "APPE"}:
            return "upload"
        if direction == "o" or value in {"DOWNLOAD", "RETR"}:
            return "download"
        if direction == "d" or value in {"DELE", "RMD"}:
            return "delete"
        if value in {"LOGIN", "USER", "PASS", "AUTH", "ACCT"}:
            return "login"
        if value in {"CONNECT", "DISCONNECT"}:
            return value.lower()
        if value in WRITE_COMMANDS:
            return "write_command"
        if value in READ_COMMANDS:
            return "read_command"
        if value:
            return "command"
        return "transfer"

    @staticmethod
    def classify_success(status: str, operation: str | None) -> bool | None:
        if status == "OK":
            return True
        if status == "FAIL":
            return False
        if status in {"CONNECT", "DISCONNECT", "FTP command"}:
            return None
        return None

    @staticmethod
    def classify_event(
        operation: str,
        command: str | None,
        success: bool | None,
        username: str | None,
        file_path: str | None,
        access_mode: str | None,
    ) -> str:
        lowered_path = (file_path or "").lower()
        normalized_user = (username or "").lower()
        normalized_command = (command or "").upper()

        if operation == "login" and success is False:
            return "failed_login"
        if operation == "login" and normalized_user in {"anonymous", "ftp"}:
            return "anonymous_login"
        if operation == "login":
            return "login"
        if normalized_command in {"SITE", "CHMOD"}:
            return "ftp_site_command"
        if any(pattern in lowered_path for pattern in SUSPICIOUS_PATH_PATTERNS):
            return "suspicious_path"
        if operation in {"upload", "write_command"}:
            return "file_upload"
        if operation == "download":
            return "file_download"
        if operation == "delete":
            return "file_delete"
        if access_mode == "a" or normalized_user in {"anonymous", "ftp"}:
            return "anonymous_activity"
        if operation == "read_command":
            return "recon"
        return "ftp_activity"

    @staticmethod
    def classify_severity(action: str) -> int:
        severity_mapping = {
            "failed_login": 2,
            "anonymous_login": 2,
            "login": 1,
            "ftp_site_command": 4,
            "suspicious_path": 4,
            "file_upload": 4,
            "file_delete": 3,
            "file_download": 2,
            "anonymous_activity": 2,
            "recon": 2,
            "ftp_activity": 1,
        }
        return severity_mapping.get(action, 1)

    @staticmethod
    def _empty_to_none(value: str | None) -> str | None:
        if value in {None, "", "-", "*"}:
            return None
        return value
