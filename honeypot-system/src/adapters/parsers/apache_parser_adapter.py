"""Adapter: ApacheParserAdapter — parses Apache access and error logs."""

import re
from datetime import datetime
from typing import Optional

from src.ports.outbound.log_parser_port import LogParser
from src.domain.models.event import ApacheEvent
from src.domain.exceptions.domain_exceptions import ParseError


ACCESS_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"
ERROR_TS_FMT = "%a %b %d %H:%M:%S.%f %Y"

ACCESS_LOG_RE = re.compile(
    r"(?P<ip>\S+)"
    r"\s+\S+\s+(?P<user>\S+)"
    r'\s+\[(?P<ts>[^\]]+)\]'
    r'\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"'
    r"\s+(?P<status>\d{3})"
    r"\s+(?P<size>\S+)"
)

ERROR_LOG_RE = re.compile(
    r"\[(?P<ts>[^\]]+)\]"
    r"\s+\[(?P<module>[^\]]+)\]"
    r"(?:\s+\[pid\s+(?P<pid>\d+)\])?"
    r"(?:\s+\[client\s+(?P<client>[^\]]+)\])?"
    r"\s+(?P<message>.+)"
)

HIGH_RISK_PATTERNS = {
    "/etc/passwd",
    "/bin/sh",
    "/bin/bash",
    "/proc/self/environ",
    "/.env",
    "/wp-config.php",
    "/cgi-bin/",
    "/vendor/phpunit",
    "/boaform/",
    "/shell",
}

RCE_PATTERNS = {
    "cmd=",
    "exec=",
    "system(",
    "bash%20-c",
    "wget",
    "curl",
    "nc ",
    "powershell",
}

TRAVERSAL_PATTERNS = {
    "../",
    "..%2f",
    "%2e%2e%2f",
    "..\\",
}

SCANNER_PATTERNS = {
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/manager/html",
    "/HNAP1",
    "/login",
    "/actuator",
}

FILE_UPLOAD_PATTERNS = {
    ".php",
    ".jsp",
    ".asp",
    ".aspx",
    ".war",
}


class ApacheParserAdapter(LogParser):
    """Parses Apache access.log and error.log lines."""

    DEFAULT_PATH = "/var/log/apache2/access.log"

    def parse(self, raw_line: str, path: str) -> Optional[ApacheEvent]:
        raw_line = raw_line.strip()

        if not raw_line:
            return None

        if "access" in path.lower():
            return self._parse_access_log(raw_line)

        elif "error" in path.lower():
            return self._parse_error_log(raw_line)

        else:
            raise ParseError(f"ApacheParserAdapter: unknown log format for path: {path}")

    def _parse_access_log(self, raw_line: str) -> Optional[ApacheEvent]:
        match = ACCESS_LOG_RE.match(raw_line)

        if not match:
            return None

        try:
            timestamp = datetime.strptime(
                match.group("ts"),
                ACCESS_TS_FMT,
            )
        except ValueError as exc:
            raise ParseError(f"ApacheParserAdapter: bad access timestamp: {exc}") from exc

        ip = match.group("ip")

        user = match.group("user")
        user = user if user not in {"-", "*"} else None

        method = match.group("method")
        request_path = match.group("path")

        status = int(match.group("status"))

        raw_size = match.group("size")
        size = int(raw_size) if raw_size.isdigit() else 0

        operation = self.classify_operation(method)
        success = self.classify_status_success(status)

        action = self.classify_event(
            method=method,
            path=request_path,
            status=status,
            success=success,
        )

        return ApacheEvent(
            timestamp=timestamp,
            source="apache-access",
            ip=ip,
            user=user,
            method=method,
            operation=operation,
            action=action,
            success=success,
            status=status,
            severity_score=self.classify_severity(action),
            path=request_path,
            size=size,
            raw=raw_line,
        )

    def _parse_error_log(self, raw_line: str) -> Optional[ApacheEvent]:
        match = ERROR_LOG_RE.match(raw_line)

        if not match:
            return None

        try:
            timestamp = datetime.strptime(
                match.group("ts"),
                ERROR_TS_FMT,
            )
        except ValueError as exc:
            raise ParseError(f"ApacheParserAdapter: bad error timestamp: {exc}") from exc

        message = match.group("message")

        client = match.group("client")
        ip = None

        if client:
            ip = client.split(":")[0].strip()

        action = self.classify_error_event(message)

        return ApacheEvent(
            timestamp=timestamp,
            source="apache-error",
            ip=ip,
            action=action,
            severity_score=self.classify_severity(action),
            message=message,
            raw=raw_line,
        )

    @staticmethod
    def classify_operation(method: str | None) -> str:
        value = (method or "").upper()

        if value in {"GET", "HEAD", "OPTIONS"}:
            return "read"

        if value in {"POST", "PUT", "PATCH"}:
            return "write"

        if value == "DELETE":
            return "delete"

        if value in {"CONNECT", "TRACE"}:
            return "tunnel"

        return "request"

    @staticmethod
    def classify_status_success(status: int | None) -> bool | None:
        if status is None:
            return None

        return 200 <= status < 400

    @staticmethod
    def classify_event(
        method: str | None,
        path: str | None,
        status: int | None,
        success: bool | None,
    ) -> str:
        normalized_path = (path or "").lower()
        normalized_method = (method or "").upper()

        if any(pattern in normalized_path for pattern in HIGH_RISK_PATTERNS):
            return "high_risk"

        if any(pattern in normalized_path for pattern in RCE_PATTERNS):
            return "rce_attempt"

        if any(pattern in normalized_path for pattern in TRAVERSAL_PATTERNS):
            return "traversal_attempt"

        if any(pattern in normalized_path for pattern in SCANNER_PATTERNS):
            return "scanner_activity"

        if (
            normalized_method in {"POST", "PUT", "PATCH"}
            and any(pattern in normalized_path for pattern in FILE_UPLOAD_PATTERNS)
        ):
            return "file_upload_attempt"

        if success is False and status == 401:
            return "unauthorized_access"

        if success is False and status == 403:
            return "forbidden_access"

        if success is False and status == 404:
            return "not_found_scan"

        return "web_activity"

    @staticmethod
    def classify_error_event(message: str | None) -> str:
        normalized_message = (message or "").lower()

        if "segmentation fault" in normalized_message:
            return "crash"

        if "permission denied" in normalized_message:
            return "permission_denied"

        if "client denied" in normalized_message:
            return "blocked_client"

        if "script not found" in normalized_message:
            return "missing_resource"

        if "php fatal error" in normalized_message:
            return "php_error"

        if "file does not exist" in normalized_message:
            return "missing_resource"

        return "apache_error"

    @staticmethod
    def classify_severity(action: str) -> int:
        severity_mapping = {
            "high_risk": 4,
            "rce_attempt": 4,
            "traversal_attempt": 3,
            "scanner_activity": 2,
            "file_upload_attempt": 4,
            "unauthorized_access": 2,
            "forbidden_access": 2,
            "not_found_scan": 1,
            "crash": 4,
            "permission_denied": 3,
            "blocked_client": 2,
            "missing_resource": 1,
            "php_error": 3,
            "apache_error": 2,
            "web_activity": 1,
        }

        return severity_mapping.get(action, 1)