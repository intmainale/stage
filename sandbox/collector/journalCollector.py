import subprocess
import json
from collector.baseCollector import BaseCollector

class JournalctlCollector(BaseCollector):
    def collect(self):
        self.logger.debug("Collecting journalctl logs")

        cmd = ["journalctl", "-f", "-o", "json"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

        for line in process.stdout:
            yield self.parse(line)

    def parse(self, raw):
        try:
            data = json.loads(raw)

            return {
                "timestamp": data.get("__REALTIME_TIMESTAMP"),
                "source": "journalctl",
                "host": data.get("_HOSTNAME"),
                "user": data.get("_UID"),
                "event_type": "system",
                "message": data.get("MESSAGE"),
                "data": data
            }

        except Exception as e:
            self.logger.error(f"journal parse error: {e}")
            return None