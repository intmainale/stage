"""Adapter: BashParserAdapter — parses bash history, journald wrapped bash events, and auditd EXECVE events."""

from pathlib import Path
import time
from datetime import datetime, timezone
from typing import Optional

from src.ports.outbound.log_parser_port import LogParser
from src.domain.models.event import BashEvent
from src.domain.exceptions.domain_exceptions import ParseError

OUTPUT_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Commands that map to "download" action
_DOWNLOAD  = {"wget ", "curl ", "fetch ", "tftp "}

# Commands that spawn interactive shells
_SHELL     = {"/bin/sh", "/bin/bash", "sh -i", "bash -i"}

# Commands related to privilege escalation
_PRIVESC   = {"sudo ", "su ", "chmod +s", "setcap "}

# Commands that establish persistence
_PERSIST   = {"crontab", "/etc/cron", ".ssh/authorized_keys", "systemctl enable", "@reboot"}

# Reconnaissance commands
_RECON     = {"whoami", "id ", "uname", "hostname", "ifconfig", "ip a", "netstat", "ss ", "ps aux", "history"}

# Lateral movement / network commands
_NETWORK   = {"ssh ", "scp ", "nc ", "ncat ", "telnet "}

class BashParserAdapter(LogParser):
    """Parses bash service events from bash history"""

    DEFAULT_PATH = "/root/.bash_history"
        
    def parse(self, raw_line: str, path: str) -> Optional[BashEvent]:
        """
        Example input:
            2026-05-15T10:42:11 path=/home/alex user=alex groups=admin,docker,sudo 1000 1231 cmd="ls -la"
        """
        try:
            raw_line = raw_line.strip()
            if not raw_line:
                return None

            return self._parse_bash_event(raw_line)

        except ParseError:
            raise
        except Exception as exc:
            raise ParseError(f"[BashParserAdapter] unexpected error: {exc}") from exc
        
    def _parse_bash_event(self, raw_line: str) -> Optional[BashEvent]:
        try:
            timestamp = datetime.fromtimestamp(
                time.time(),
                tz=timezone.utc,
            ).strftime(OUTPUT_TS_FMT)

        except Exception as exc:
            raise ParseError(f"[BashParserAdapter] invalid timestamp: {exc}") from exc
        
        action = self.classify_event(raw_line)
        severity_score = self.classify_severity(action)

        event = BashEvent(
            timestamp = timestamp,
            source="bash",
            cmd = raw_line,
            action = action,
            severity_score = severity_score,
        )
        
        return event


    # ── Classification helpers ────────────────────────────────────────────────

    @staticmethod
    def classify_event(cmd: str) -> str:
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
    def classify_severity(action: str) -> int:
        """Returns a 1-4 severity score matching SCORE_TO_SEVERITY."""
        if action in {"download", "privilege_escalation", "persistence"}:
            return 4   # critical
        if action in {"shell", "network"}:
            return 3   # high
        if action == "recon":
            return 2   # medium
        return 1       # low
