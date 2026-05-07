from curses import raw
import re

class Normalizer:
    def __init__(self, logger):
        self.logger = logger

    # -------------------------
    # ENTRY POINT
    # -------------------------
    def normalize(self, event: str) -> str:
        source = event.get("source")
        self.logger.debug(f"Normalizing event from source: {source}")
        message = event.get("message")
        if source == "auditd":
            return self._normalize_auditd(message)

        if source == "bash":
            return self._normalize_bash(message)

        if source == "journal":
            return self._normalize_journal(message)

        return self._normalize_generic(event)

    # -------------------------
    # BASH HISTORY
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


    def _extract_url(self, cmd):
        match = re.search(r"(https?://[^\s]+)", cmd)
        return match.group(1) if match else None


    def _normalize_bash(self, event):
        cmd = event

        if not cmd:
            return None

        cmd_lower = cmd.lower()

        action = self._classify_bash_command(cmd_lower)
        severity = self._classify_bash_severity(action)

        url = self._extract_url(cmd)

        #
        # escape for line protocol
        #

        escaped_cmd = cmd.replace("\\", "\\\\").replace('"', '\\"')

        fields = [
            f'command="{escaped_cmd}"',
            f'severity="{severity}"',
        ]

        if url is not None:
            escaped_url = url.replace('"', '\\"')
            fields.append(f'url="{escaped_url}"')

        tags = f"event_type={action}"

        return f"bash_history,{tags} {','.join(fields)}"

    # -------------------------
    # AUDITD
    # -------------------------

    USEFUL_RECORD_TYPES = {
        "SYSCALL",
        "EXECVE",
        "CWD",
        "PATH",
        "USER_AUTH",
        "USER_LOGIN",
        "USER_ACCT",
        "CRED_ACQ",
        "CRED_DISP",
        "ADD_USER",
        "DEL_USER",
        "ADD_GROUP",
        "DEL_GROUP",
        "SOCKADDR",
        "NETFILTER_CFG",
        "SERVICE_START",
        "SERVICE_STOP",
        "CONFIG_CHANGE",
        "AVC",
        "USER_CMD",
        "ANOM_LOGIN_FAILURES",
        "ANOM_PROMISCUOUS",
        "ANOM_ABEND",
        "LOGIN",
    }


    def _extract_field(self, pattern, raw):
        match = re.search(pattern, raw)
        return match.group(1) if match else None


    def _extract_kv(self, raw, key):
        """
        supports:
            key=value
            key="value"
        """
        match = re.search(rf'{key}="?([^"\s]+)"?', raw)
        return match.group(1) if match else None


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

    def _escape_lp_string(self, v: str) -> str:
        if v is None:
            return None
        return (
            str(v)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", " ")
            .replace("\r", " ")
        )
    
    def _fmt_field(self, k, v):
        if v is None:
            return None

        # booleans
        if isinstance(v, bool):
            return f"{k}={str(v).lower()}"

        # ints
        if isinstance(v, int):
            return f"{k}={v}i"

        # floats
        if isinstance(v, float):
            return f"{k}={v}"

        # numeric strings (optional heuristic)
        if isinstance(v, str) and v.isdigit():
            return f"{k}={v}i"

        # string fallback (IMPORTANT)
        safe = self._escape_lp_string(v)
        return f'{k}="{safe}"'
    
    def _normalize_auditd(self, event):
        raw = event

        # example:
        # type=SYSCALL msg=audit(...)
        record_type = self._extract_field(r"type=([A-Z_]+)", raw)

        audit_event_id = self._extract_field(
            r"msg=audit\([0-9]+\.[0-9]+:(\d+)\)",
            raw
        )
        if not record_type:
            return None

        # ignore noisy records
        if record_type not in self.USEFUL_RECORD_TYPES:
            return None

        # extracted fields
        uid = self._extract_kv(raw, "uid")
        auid = self._extract_kv(raw, "auid")
        pid = self._extract_kv(raw, "pid")
        ppid = self._extract_kv(raw, "ppid")
        exe = self._extract_kv(raw, "exe")
        comm = self._extract_kv(raw, "comm")
        syscall = self._extract_kv(raw, "syscall")
        cwd = self._extract_kv(raw, "cwd")
        addr = self._extract_kv(raw, "addr")
        terminal = self._extract_kv(raw, "terminal")
        success = self._extract_kv(raw, "success")
        path = self._extract_kv(raw, "name")
        key = self._extract_kv(raw, "key")

        # EXECVE arguments
        argc = self._extract_kv(raw, "argc")

        args = []
        if argc:
            try:
                for i in range(int(argc)):
                    arg = self._extract_kv(raw, f"a{i}")
                    if arg:
                        args.append(arg)
            except Exception:
                pass

        #
        # TELEGRAF METRIC FORMAT
        #

        tags = f"event_type={record_type.lower()}"

        if audit_event_id is not None:
            tags += f",audit_event_id={audit_event_id}"
        
        fields = [
            f'severity="{self._classify_severity(record_type)}"',
            f'action="{self._classify_action(record_type)}"',
            f'raw="{self._escape_lp_string(raw)}"',
        ]
        #
        # only include fields if they exist
        #

        optional_fields = {
            "uid": uid,
            "auid": auid,
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "comm": comm,
            "syscall": syscall,
            "cwd": cwd,
            "addr": addr,
            "terminal": terminal,
            "success": success,
            "path": path,
            "key": key,
        }

        for k, v in optional_fields.items():
            if v is not None:
                f = self._fmt_field(k, v)
                if f:
                    fields.append(f)

        if args:
            fields.append(f"args={' '.join(args)}")

        return f"auditd_log,{tags} {','.join(fields)}"

    # -------------------------
    # JOURNALCTL
    # -------------------------

    USEFUL_JOURNAL_PATTERNS = {
        "ssh",
        "sudo",
        "su",
        "systemd",
        "kernel",
        "pam",
        "cron",
        "session",
        "authentication",
        "failed password",
        "invalid user",
        "accepted password",
        "new session",
        "removed session",
        "segfault",
        "oom",
        "iptables",
        "firewalld",
        "ufw",
        "docker",
        "podman",
    }


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


    def _normalize_journal(self, event):
        raw = event
        msg_lower = raw.lower()

        #
        # ignore noisy/uninteresting logs
        #

        if not any(p in msg_lower for p in self.USEFUL_JOURNAL_PATTERNS):
            return None

        #
        # extract common fields
        #

        pid = self._extract_field(r"\[(\d+)\]", raw)

        user = self._extract_field(r"user[=\s]([a-zA-Z0-9_-]+)", raw)
        if user is None:
            user = self._extract_field(r"for ([a-zA-Z0-9_-]+)", raw)

        ip = self._extract_field(
            r"from ([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
            raw
        )

        service = self._extract_field(r"^([a-zA-Z0-9_.@-]+)", raw)

        session_id = self._extract_field(r"session\s+([0-9]+)", msg_lower)

        #
        # tags
        #

        tags = f"event_type={self._classify_journal_event(msg_lower)}"

        if service is not None:
            tags += f",service={service}"

        #
        # fields
        #

        fields = [
            f'severity="{self._classify_journal_severity(msg_lower)}"',
            f'message="{raw}"',
            f'pid="{pid}"',
            f'user="{user}"',
            f'src_ip="{ip}"',
            f'session_id="{session_id}"',
        ]

        return f"systemd-journald,{tags} {','.join(fields)}"
    # -------------------------
    # FALLBACK
    # -------------------------
    def _normalize_generic(self, event):
        return f"generic_log,source={event.get('source', '')},event_type=generic,severity=info message=\"{event.get('message', '').replace('\"', '\\\"')}\""