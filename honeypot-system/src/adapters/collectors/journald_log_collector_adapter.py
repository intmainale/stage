"""
Adapter: JournaldLogCollector
Streams entries from systemd journal via the `journalctl` subprocess.
Falls back to a file path when systemd is unavailable.
"""

import subprocess
from typing import Iterator

from src.ports.outbound.log_collector_port import LogCollector
from src.domain.exceptions.domain_exceptions import CollectionError
from config.settings import Settings


class JournaldLogCollectorAdapter(LogCollector):
    """
    Spawns `journalctl -f -o short-iso` and yields each line.
    Configured via settings keys:
      collectors.journald.unit   (optional unit filter, e.g. "sshd.service")
      collectors.journald.lines  (number of historical lines to tail, default 100)
    """

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._unit:  str = cfg.get("collectors.journald.unit",  "")
        self._lines: str = cfg.get("collectors.journald.lines", "100")

    def _build_cmd(self) -> list[str]:
        cmd = ["journalctl", "-n", self._lines, "-o", "short-iso", "--no-pager"]
        if self._unit:
            cmd.extend(["-u", self._unit])
        return cmd

    def collect(self) -> Iterator[str]:
        cmd = self._build_cmd()
        self._L.info("JournaldLogCollectorAdapter: running %s", " ".join(cmd))
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                yield line
            proc.wait()
            if proc.returncode not in (0, -15):
                err = proc.stderr.read() if proc.stderr else ""
                raise CollectionError(f"journalctl exited with {proc.returncode}: {err}")
            
        except FileNotFoundError as exc:
            raise CollectionError("journalctl not found") from exc
            
        except OSError as exc:
            raise CollectionError(f"JournaldLogCollectorAdapter: OS error: {exc}") from exc