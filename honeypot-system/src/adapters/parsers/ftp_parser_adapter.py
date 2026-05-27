"""Adapter: FTPParserAdapter - parses ProFTPD xferlog and extended.log lines."""

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
EXTENDED_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

PROFTPD_EXTENDED_RE = re.compile(
    r'(?P<host>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3}|-)\s+(?P<size>\d+|-)"
)
HOSTNAME_IPV4_RE = re.compile(r"(?<!\d)(?P<octets>\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3})(?!\d)")

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
READ_COMMANDS = {"RETR", "LIST", "NLST", "MLSD", "SIZE", "MDTM", "PWD", "CWD", "FEAT"}
AUTH_COMMANDS = {"USER", "PASS", "ACCT", "AUTH"}
SESSION_COMMANDS = {"TYPE", "PASV", "PORT", "QUIT", "LANG", "OPTS", "OPTS_UTF8", "OPTS_MLST"}


class FTPParserAdapter(LogParser):
    """Parses ProFTPD 1.3.5 xferlog and extended.log lines."""

    DEFAULT_PATH = "/var/log/vsftpd.log"

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = Path(path) if path else Path(self.DEFAULT_PATH)

    def parse(self, raw_line: str) -> Optional[FTPEvent]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        if "xferlog" in self.path:
            event = self._parse_xferlog(raw_line)
        else:
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
        remote_ip = remote_host
        if not all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in remote_host.split(".")):
            host_match = HOSTNAME_IPV4_RE.search(remote_host)
            remote_ip = host_match.group("octets").replace("-", ".") if host_match else None

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
            ip=remote_ip,
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
        match = PROFTPD_EXTENDED_RE.match(raw_line)
        if not match:
            return None

        try:
            timestamp = datetime.strptime(match.group("ts"), EXTENDED_TS_FMT)
        except ValueError as exc:
            raise ParseError(f"FTPParserAdapter: bad ProFTPD extended timestamp: {exc}") from exc

        request = match.group("request").strip()
        command, _, raw_argument = request.partition(" ")
        command = command.upper() if command else None
        argument = raw_argument if raw_argument and raw_argument not in {"-", "*"} else None

        file_path = self.extract_file_path(command, argument)
        status = match.group("status")
        status = status if status != "-" else None
        success = self.classify_status_success(status)
        operation = self.classify_operation(None, command)
        username = match.group("user")
        username = username if username not in {"-", "*"} else None
        action = self.classify_event(
            operation=operation,
            command=command,
            success=success,
            username=username,
            file_path=file_path,
            access_mode=None,
        )
        size = match.group("size")
        bytes_transferred = int(size) if size.isdigit() else None

        remote_host = match.group("host")
        remote_ip = remote_host
        if not all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in remote_host.split(".")):
            host_match = HOSTNAME_IPV4_RE.search(remote_host)
            remote_ip = host_match.group("octets").replace("-", ".") if host_match else None

        return FTPEvent(
            timestamp=timestamp,
            source="ftp-extended",
            ip=remote_ip,
            username=username,
            command=command,
            operation=operation,
            action=action,
            success=success,
            status=status,
            severity_score=self.classify_severity(action),
            file_path=file_path,
            bytes_transferred=bytes_transferred,
            message=request,
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
        if value in {"CONNECT", "DISCONNECT", "QUIT"}:
            return value.lower()
        if value in WRITE_COMMANDS:
            return "write_command"
        if value in READ_COMMANDS:
            return "read_command"
        if value in SESSION_COMMANDS:
            return "session"
        if value:
            return "command"
        return "transfer"

    @staticmethod
    def classify_status_success(status: str | None) -> bool | None:
        if status is None:
            return None
        try:
            status_code = int(status)
        except ValueError:
            return None
        return 200 <= status_code < 400

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
        if operation == "session":
            return "session"
        if operation == "quit":
            return "disconnect"
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
            "session": 1,
            "disconnect": 1,
            "ftp_activity": 1,
        }
        return severity_mapping.get(action, 1)

    @staticmethod
    def extract_file_path(command: str | None, argument: str | None) -> str | None:
        if not argument:
            return None
        if command in {"USER", "PASS", "TYPE", "PASV", "PORT", "LANG", "OPTS", "OPTS_UTF8", "OPTS_MLST"}:
            return None
        if command == "MFMT":
            parts = argument.split(maxsplit=1)
            return parts[1] if len(parts) == 2 else None
        return argument
