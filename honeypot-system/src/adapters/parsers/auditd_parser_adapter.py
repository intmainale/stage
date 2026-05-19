"""Adapter: AuditdParserAdapter — parses auditd EXECVE events."""

import re
from datetime import datetime, timezone
from typing import Optional

from src.ports.outbound.log_parser_port import LogParser
from src.domain.models.event import AuditdExecEvent
from src.domain.exceptions.domain_exceptions import ParseError

AUDIT_MSG_RE = re.compile(
    r"audit\((?P<ts>[0-9]+\.[0-9]+):(?P<id>[0-9]+)\)"
)

KEY_VALUE_RE = re.compile(r'(\w+)=(".*?"|\S+)')

class AuditdParserAdapter(LogParser):
    """
    Parses ONLY auditd execve/syscall events.
    """

    def parse(self, raw_line: str) -> Optional[AuditdExecEvent]:
        """
        Example input:
            type=SYSCALL msg=audit(1716112345.123:456):
            arch=c000003e syscall=59 success=yes exe="/usr/bin/curl"
            comm="curl" pid=1234 uid=1000   ppid=5678?????
        """

        if not raw_line.strip():
            raise ParseError("AuditdParserAdapter: empty line")
        
        # --- base fields ---
        ts = None
        event_id = None

        audit_match = AUDIT_MSG_RE.search(raw_line)
        if audit_match:
            ts = float(audit_match.group("ts"))
            event_id = int(audit_match.group("id"))

        # --- key=value extraction ---
        fields = {}
        for k, v in KEY_VALUE_RE.findall(raw_line):
            fields[k] = v.strip('"')

        # --- filter execve/syscall events only ---
        syscall = fields.get("syscall")
        if syscall not in ("59", "execve"):  # 59 = execve on x86_64
            return None

        event = AuditdExecEvent(
            timestamp=ts,
            event_id=event_id,

            pid=int(fields["pid"]) if "pid" in fields else None,
            ppid=int(fields["ppid"]) if "ppid" in fields else None,
            uid=int(fields["uid"]) if "uid" in fields else None,

            exe=fields.get("exe"),
            comm=fields.get("comm"),

            success=(fields.get("success") == "yes"),

            syscall=syscall,

            raw=raw_line
        )

        return event