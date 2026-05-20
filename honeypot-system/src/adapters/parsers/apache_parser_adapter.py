"""Adapter: ApacheParser — parses Apache combined-log-format lines."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from src.ports.outbound.log_parser_port import LogParser
from src.domain.models.event import ApacheEvent
from src.domain.exceptions.domain_exceptions import ParseError

# Combined Log Format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
_PATTERN = re.compile(
    r'(?P<ip>\S+)'
    r'\s+\S+\s+(?P<user>\S+)'
    r'\s+\[(?P<ts>[^\]]+)\]'
    r'\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
)
_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

HIGH_RISK_PATTERNS = [
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
]

RCE_PATTERNS = [
    "cmd=",
    "exec=",
    "system(",
    "bash%20-c",
    "wget",
    "curl",
    "nc ",
    "powershell",
]

TRAVERSAL_PATTERNS = [
    "../",
    "..%2f",
    "%2e%2e%2f",
    "..\\",
]

SCANNER_PATTERNS = [
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/manager/html",
    "/HNAP1",
    "/login",
    "/actuator",
]

FILE_UPLOAD_PATTERNS = [
    ".php",
    ".jsp",
    ".asp",
    ".aspx",
    ".war",
]

class ApacheParserAdapter(LogParser):
    """Parses Apache / Nginx combined-log-format access log lines."""

    def parse(self, raw_line: str) -> Optional[ApacheEvent]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None
 
        m = _PATTERN.match(raw_line)
        if not m:
            return None

        try:
            ts = datetime.strptime(m.group("ts"), _TS_FMT)
        except ValueError as exc:
            raise ParseError(f"ApacheParser: bad timestamp: {exc}") from exc

        event = ApacheEvent(
            timestamp = ts,
            source    = "apache",
            ip        = m.group("ip"),
            user      = m.group("user"),
            method    = m.group("method"),
            path      = m.group("path"),
            status    = int(m.group("status")),
            size      = int(m.group("size")),
        )

        return event

    @staticmethod
    def classify_event(path: str) -> str:
        path = path.lower()
        if any(p in path for p in HIGH_RISK_PATTERNS):
            return "high_risk"
        if any(p in path for p in RCE_PATTERNS):
            return "rce_attempt"
        if any(p in path for p in TRAVERSAL_PATTERNS):
            return "traversal_attempt"
        if any(p in path for p in SCANNER_PATTERNS):
            return "scanner_activity"
        if any(p in path for p in FILE_UPLOAD_PATTERNS):
            return "file_upload_attempt"
        
        return "normal"
    
    @staticmethod
    def classify_severity(event_type: str) -> int:
        severity_mapping = {
            "high_risk": 4,
            "rce_attempt": 3,
            "traversal_attempt": 3,
            "scanner_activity": 2,
            "file_upload_attempt": 3,
            "normal": 1,
        }

        return severity_mapping.get(event_type, 0)