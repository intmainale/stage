import json
import re
import time


class Normalizer:
    def __init__(self, logger):
        self.logger = logger

    # -------------------------
    # ENTRY POINT
    # -------------------------
    def normalize(self, event: dict):
        source = event.get("source")
        raw = event.get("message", "")

        if source == "auditd":
            return self._normalize_auditd(raw)

        if source == "bash":
            return self._normalize_bash(raw)

        if source == "journal":
            return self._normalize_journal(raw)

        return self._normalize_generic(event)

    # -------------------------
    # HELPERS
    # -------------------------
    def _ts(self):
        return int(time.time() * 1e9)

    def _extract(self, pattern, raw):
        m = re.search(pattern, raw)
        return m.group(1) if m else None

    # -------------------------
    # BASH (UNCHANGED SEMANTICS)
    # -------------------------
    def _classify_bash_command(self, cmd_lower):
        #
        # malware download/execution
        #

        if any(x in cmd_lower for x in [
            "wget ",
            "curl ",
            "fetch ",
            "tftp ",
        ]):
            return "download"

        #
        # shell spawning
        #

        if any(x in cmd_lower for x in [
            "/bin/sh",
            "/bin/bash",
            "sh -i",
            "bash -i",
        ]):
            return "shell"

        #
        # privilege escalation
        #

        if any(x in cmd_lower for x in [
            "sudo ",
            "su ",
            "chmod +s",
            "setcap ",
        ]):
            return "privilege_escalation"

        #
        # persistence
        #

        if any(x in cmd_lower for x in [
            "crontab",
            "/etc/cron",
            ".ssh/authorized_keys",
            "systemctl enable",
            "@reboot",
        ]):
            return "persistence"

        #
        # reconnaissance
        #

        if any(x in cmd_lower for x in [
            "whoami",
            "id",
            "uname",
            "hostname",
            "ifconfig",
            "ip a",
            "netstat",
            "ss ",
            "ps aux",
            "history",
        ]):
            return "recon"

        #
        # lateral movement/networking
        #

        if any(x in cmd_lower for x in [
            "ssh ",
            "scp ",
            "nc ",
            "ncat ",
            "telnet ",
        ]):
            return "network"

        return "command"


    def _classify_bash_severity(self,action):
        high = {
            "download",
            "privilege_escalation",
            "persistence",
        }

        medium = {
            "shell",
            "network",
        }

        if action in high:
            return "critical"

        if action in medium:
            return "warning"

        return "info"
    

    def _normalize_bash(self, cmd):
        if not cmd:
            return None

        cmd_lower = cmd.lower()

        action = self._classify_bash_command(cmd_lower)
        severity = self._classify_bash_severity(action)

        url = self._extract(r"(https?://[^\s]+)", cmd)

        return json.dumps({
            "measurement": "bash_history",
            "time": self._ts(),
            "tags": {
                "event_type": action
            },
            "fields": {
                "command": cmd,
                "severity": severity,
                "url": url
            }
        })

    # -------------------------
    # AUDITD (SAME TAGS/FIELDS AS BEFORE)
    # -------------------------
    def _classify_severity(self, record_type):
        high = {
            "EXECVE",
            "USER_AUTH",
            "USER_LOGIN",
            "ANOM_LOGIN_FAILURES",
            "ANOM_PROMISCUOUS",
            "AVC",
            "ADD_USER",
            "DEL_USER",
            "NETFILTER_CFG",
            "CONFIG_CHANGE",
        }

        medium = {
            "SYSCALL",
            "USER_CMD",
            "SERVICE_START",
            "SERVICE_STOP",
            "LOGIN",
        }

        if record_type in high:
            return "high"

        if record_type in medium:
            return "medium"

        return "info"


    def _classify_action(self, record_type):
        mapping = {
            "EXECVE": "process_execution",
            "SYSCALL": "syscall",
            "USER_AUTH": "authentication",
            "USER_LOGIN": "login",
            "USER_ACCT": "account_usage",
            "USER_CMD": "command_execution",
            "ADD_USER": "user_created",
            "DEL_USER": "user_deleted",
            "ADD_GROUP": "group_created",
            "DEL_GROUP": "group_deleted",
            "SERVICE_START": "service_started",
            "SERVICE_STOP": "service_stopped",
            "CONFIG_CHANGE": "configuration_change",
            "AVC": "selinux_denied",
            "SOCKADDR": "network_connection",
            "NETFILTER_CFG": "firewall_change",
            "LOGIN": "login",
        }

        return mapping.get(record_type)
    

    def _normalize_auditd(self, raw):
        record_type = self._extract(r"type=([A-Z_]+)", raw)
        if not record_type:
            return None

        audit_event_id = self._extract(r"msg=audit\([0-9.]+:(\d+)\)", raw)

        uid = self._extract(r"uid=(\d+)", raw)
        auid = self._extract(r"auid=(\d+)", raw)
        pid = self._extract(r"pid=(\d+)", raw)
        ppid = self._extract(r"ppid=(\d+)", raw)
        exe = self._extract(r'exe="([^"]+)"', raw)
        comm = self._extract(r'comm="([^"]+)"', raw)
        syscall = self._extract(r"syscall=(\d+)", raw)
        cwd = self._extract(r'cwd="([^"]+)"', raw)
        addr = self._extract(r"addr=([^\s]+)", raw)
        terminal = self._extract(r"terminal=([^\s]+)", raw)
        success = self._extract(r"success=([^\s]+)", raw)
        path = self._extract(r'name="([^"]+)"', raw)
        key = self._extract(r'key="([^"]+)"', raw)

        argc = self._extract(r"argc=(\d+)", raw)

        args = []
        if argc:
            try:
                for i in range(int(argc)):
                    a = self._extract(rf'a{i}="([^"]+)"', raw)
                    if a:
                        args.append(a)
            except:
                pass

        return json.dumps({
            "measurement": "auditd_log",
            "time": self._ts(),

            # ---------------- tags (UNCHANGED LOGIC) ----------------
            "tags": {
                "event_type": record_type.lower(),
                "audit_event_id": audit_event_id
            },

            # ---------------- fields (UNCHANGED LOGIC) ----------------
            "fields": {
                "severity": self._classify_severity(record_type),
                "action": self._classify_action(record_type),
                "raw": raw,

                "uid": int(uid) if uid else None,
                "auid": int(auid) if auid else None,
                "pid": int(pid) if pid else None,
                "ppid": int(ppid) if ppid else None,
                "exe": exe,
                "comm": comm,
                "syscall": int(syscall) if syscall else None,
                "cwd": cwd,
                "addr": addr,
                "terminal": terminal,
                "success": success,
                "path": path,
                "key": key,
                "args": " ".join(args) if args else None
            }
        })

    # -------------------------
    # JOURNAL (UNCHANGED LOGIC)
    # -------------------------
    def _classify_journal_event(self, msg_lower):
        if "failed password" in msg_lower:
            return "ssh_failed_login"

        if "accepted password" in msg_lower:
            return "ssh_login"

        if "invalid user" in msg_lower:
            return "ssh_invalid_user"

        if "sudo" in msg_lower:
            return "sudo_command"

        if "su:" in msg_lower:
            return "su_switch"

        if "new session" in msg_lower:
            return "session_open"

        if "removed session" in msg_lower:
            return "session_close"

        if "segfault" in msg_lower:
            return "segfault"

        if "oom" in msg_lower or "out of memory" in msg_lower:
            return "oom_killer"

        if "iptables" in msg_lower or "ufw" in msg_lower:
            return "firewall"

        if "docker" in msg_lower or "podman" in msg_lower:
            return "container"

        if "systemd" in msg_lower:
            return "systemd"

        return "system"


    def _classify_journal_severity(self, msg_lower):
        critical_patterns = [
            "failed",
            "failure",
            "denied",
            "segfault",
            "panic",
            "oom",
            "attack",
            "invalid user",
            "authentication failure",
        ]

        warning_patterns = [
            "sudo",
            "iptables",
            "ufw",
            "firewalld",
            "refused",
        ]

        if any(x in msg_lower for x in critical_patterns):
            return "critical"

        if any(x in msg_lower for x in warning_patterns):
            return "warning"

        return "info"
    

    def _normalize_journal(self, raw):
        msg_lower = raw.lower()

        pid = self._extract(r"\[(\d+)\]", raw)
        user = self._extract(r"user[=\s]([a-zA-Z0-9_-]+)", raw)
        ip = self._extract(r"from ([0-9.]+)", raw)
        service = self._extract(r"^([a-zA-Z0-9_.@-]+)", raw)

        session_id = self._extract(r"session\s+(\d+)", msg_lower)

        return json.dumps({
            "measurement": "systemd_journald",
            "time": self._ts(),

            "tags": {
                "event_type": self._classify_journal_event(msg_lower),
                "service": service
            },

            "fields": {
                "severity": self._classify_journal_severity(msg_lower),
                "message": raw,
                "pid": int(pid) if pid else None,
                "user": user,
                "src_ip": ip,
                "session_id": int(session_id) if session_id else None
            }
        })

    # -------------------------
    # GENERIC
    # -------------------------
    def _normalize_generic(self, event):
        return json.dumps({
            "measurement": "generic_log",
            "time": self._ts(),
            "tags": {
                "source": event.get("source"),
                "event_type": "generic"
            },
            "fields": {
                "message": event.get("message")
            }
        })