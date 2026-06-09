"""Adapter: AuditdParserAdapter — parses auditd EXECVE/SYSCALL events."""

import re
from datetime import datetime, timezone
from typing import Optional

from src.ports.outbound.log_parser_port import LogParser
from src.domain.models.event import AuditdExecEvent
from src.domain.exceptions.domain_exceptions import ParseError, TimestampError


AUDIT_MSG_RE = re.compile(
    r"audit\((?P<ts>[0-9]+\.[0-9]+):(?P<id>[0-9]+)\)"
)

OUTPUT_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

KEY_VALUE_RE = re.compile(r'(\w+)=(".*?"|\S+)')

# ---------------------------------------------------------------------------
# Classification pattern sets — keyed on full exe path and short comm name.
# Mirrors the pattern-set approach in BashParserAdapter but uses exact exe
# paths (preferred) with comm as a fallback, since auditd supplies both.
# ---------------------------------------------------------------------------

_DOWNLOAD_EXES = {
    "/usr/bin/wget", "/bin/wget",
    "/usr/bin/curl", "/bin/curl",
    "/usr/bin/fetch",
    "/usr/bin/tftp", "/usr/bin/atftp",
    "/usr/bin/axel",
}
_DOWNLOAD_COMMS = {"wget", "curl", "fetch", "tftp", "atftp", "axel"}

_SHELL_EXES = {
    "/bin/sh", "/usr/bin/sh",
    "/bin/bash", "/usr/bin/bash",
    "/bin/dash", "/usr/bin/dash",
    "/bin/zsh", "/usr/bin/zsh",
    "/bin/ksh", "/usr/bin/ksh",
    "/usr/bin/python", "/usr/bin/python3",
    "/usr/bin/perl", "/usr/bin/ruby",
    "/usr/bin/lua",
}
_SHELL_COMMS = {"sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "lua"}

_PRIVESC_EXES = {
    "/usr/bin/sudo", "/bin/sudo",
    "/usr/bin/su", "/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec",
    "/usr/sbin/visudo",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/passwd",
}
_PRIVESC_COMMS = {"sudo", "su", "newgrp", "pkexec", "visudo", "chsh", "chfn", "passwd"}

_PERSIST_EXES = {
    "/usr/bin/crontab",
    "/usr/bin/at", "/usr/bin/atd",
    "/usr/bin/systemctl", "/bin/systemctl",
    "/usr/sbin/update-rc.d",
    "/usr/sbin/insserv",
}
_PERSIST_COMMS = {"crontab", "at", "atd", "systemctl", "update-rc.d", "insserv"}

_RECON_EXES = {
    "/usr/bin/whoami",
    "/usr/bin/id",
    "/bin/uname", "/usr/bin/uname",
    "/bin/hostname", "/usr/bin/hostname",
    "/sbin/ifconfig", "/usr/sbin/ifconfig",
    "/sbin/ip", "/usr/sbin/ip", "/bin/ip",
    "/bin/netstat", "/usr/bin/netstat",
    "/usr/sbin/ss",
    "/bin/ps", "/usr/bin/ps",
    "/usr/bin/find",
    "/usr/bin/locate", "/usr/bin/mlocate",
    "/usr/bin/env",
    "/usr/bin/w", "/usr/bin/who",
    "/usr/bin/last", "/usr/bin/lastlog",
    "/usr/bin/lsof",
}
_RECON_COMMS = {
    "whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat",
    "ss", "ps", "find", "locate", "mlocate", "env", "w", "who",
    "last", "lastlog", "lsof",
}

_NETWORK_EXES = {
    "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/sftp",
    "/usr/bin/nc", "/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/netcat",
    "/usr/bin/telnet",
    "/usr/bin/ftp",
    "/usr/bin/nmap",
    "/usr/bin/masscan",
    "/usr/bin/socat",
    "/usr/bin/proxychains", "/usr/bin/proxychains4",
}
_NETWORK_COMMS = {
    "ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet", "ftp",
    "nmap", "masscan", "socat", "proxychains", "proxychains4",
}

_DATA_EXFIL_EXES = {
    "/usr/bin/rsync",
    "/usr/bin/scp",
    "/usr/bin/ftp",
    "/usr/bin/sftp",
}
_DATA_EXFIL_COMMS = {"rsync", "scp", "ftp", "sftp"}


class AuditdParserAdapter(LogParser):
    """Parses ONLY auditd execve/syscall events."""

    DEFAULT_PATH = "/var/log/audit/audit.log"

    def parse(self, raw_line: str, path: str) -> Optional[AuditdExecEvent]:
        """
        Example input:
            type=SYSCALL msg=audit(1716112345.123:456):
            arch=c000003e syscall=59 success=yes exe="/usr/bin/curl"
            comm="curl" pid=1234 uid=1000 ppid=5678
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None
        
        self._L.debug("AuditdParserAdapter: parsing audit line")
        return self._parse_execve_event(raw_line)

    def _parse_execve_event(self, raw_line: str) -> Optional[AuditdExecEvent]:
        match = AUDIT_MSG_RE.search(raw_line)
        if not match:
            raise ParseError("AuditdParserAdapter: invalid audit log format")

        try:
            ts = float(match.group("ts"))
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            timestamp = dt.astimezone(timezone.utc).strftime(OUTPUT_TS_FMT)
            self._L.debug(
                "AuditdParserAdapter: parsed timestamp=%s event_id=%s",
                timestamp,
                match.group("id"),
            )

        except ValueError as exc:
            raise TimestampError(f"AuditdParserAdapter: invalid auditd timestamp format") from exc

        event_id = int(match.group("id"))

        # --- key=value extraction ---
        fields: dict[str, str] = {}
        for k, v in KEY_VALUE_RE.findall(raw_line):
            fields[k] = v.strip('"')

        # --- filter execve/syscall events only ---
        syscall = fields.get("syscall")
        if syscall not in ("59", "execve"):  # 59 = execve on x86_64
            return None

        pid = int(fields["pid"]) if "pid" in fields else None
        ppid = int(fields["ppid"]) if "ppid" in fields else None
        uid = int(fields["uid"]) if "uid" in fields else None

        exe = fields.get("exe")
        comm = fields.get("comm")

        success = fields.get("success") == "yes"
    
        action = self.classify_event(exe=exe, comm=comm, uid=uid)
        severity_score = self.classify_severity(action)

        self._L.debug(
            "AuditdParserAdapter: event exe=%s comm=%s uid=%s success=%s syscall=%s pid=%s ppid=%s event_id=%s action=%s severity_score=%s",
            exe,
            comm,
            uid,
            success,
            syscall,
            pid,
            ppid,
            event_id,
            action,
            severity_score,
        )

        auditd_event = AuditdExecEvent(
            timestamp=timestamp,
            source="auditd",
            event_id=event_id,
            pid=pid,
            ppid=ppid,
            uid=uid,
            exe=exe,
            comm=comm,
            success=success,
            syscall=syscall,
            action=action,
            severity_score=severity_score,
            raw=raw_line,
        )

        self._L.debug("AuditdParserAdapter: parsed event: %s", auditd_event)
        return auditd_event

    # ── Classification helpers ────────────────────────────────────────────────

    @staticmethod
    def classify_event(
        exe: str | None,
        comm: str | None,
        uid: int | None
    ) -> str:
        """
        Classify an execve event into a named action.

        Resolution order:
          1. exe path (exact, most reliable)
          2. comm name (fallback — kernel strips to 15 chars, may be truncated)
          3. uid-based heuristic for root-level generic execution
        """
        normalized_exe = (exe or "").lower()
        normalized_comm = (comm or "").lower()

        # Download tools
        if normalized_exe in _DOWNLOAD_EXES or normalized_comm in _DOWNLOAD_COMMS:
            return "download"

        # Privilege escalation
        if normalized_exe in _PRIVESC_EXES or normalized_comm in _PRIVESC_COMMS:
            return "privilege_escalation"

        # Persistence mechanisms
        if normalized_exe in _PERSIST_EXES or normalized_comm in _PERSIST_COMMS:
            return "persistence"

        # Shell / scripting interpreter spawn
        if normalized_exe in _SHELL_EXES or normalized_comm in _SHELL_COMMS:
            return "shell_spawn"

        # Network / lateral movement
        if normalized_exe in _NETWORK_EXES or normalized_comm in _NETWORK_COMMS:
            return "network"

        # Recon / enumeration
        if normalized_exe in _RECON_EXES or normalized_comm in _RECON_COMMS:
            return "recon"

        if normalized_exe in _DATA_EXFIL_EXES or normalized_comm in _DATA_EXFIL_COMMS:
            return "data_exfiltration"
        
        # Root-level execution not matching any known category
        if uid == 0:
            return "root_exec"

        return "exec"

    @staticmethod
    def classify_severity(action: str) -> int:
        """Returns a 1-4 severity score matching SCORE_TO_SEVERITY."""
        severity_mapping = {
            "download":            4,  # critical — common in post-exploitation
            "privilege_escalation": 4,  # critical
            "persistence":         4,  # critical
            "shell_spawn":         3,  # high
            "network":             3,  # high
            "recon":               2,  # medium
            "root_exec":           2,  # medium
            "exec":                1,  # low
        }
        return severity_mapping.get(action, 1)
