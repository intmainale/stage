import subprocess
import json
from collector.baseCollector import BaseCollector
from time import time

class AuditdCollector(BaseCollector):
    def collect(self):
        cmd = ["ausearch", "-i", "-ts", "recent"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

        for line in process.stdout:
            parsed = self.parse(line)
            if parsed:
                yield parsed

    def parse(self, raw):
        try:
            return {
                "timestamp": time(),
                "source": "auditd",
                "event_type": "syscall",
                "message": raw.strip(),
                "data": {"raw": raw}
            }
        except Exception as e:
            self.logger.error(f"audit parse error: {e}")
            return None