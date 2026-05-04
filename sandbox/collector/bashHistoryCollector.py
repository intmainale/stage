import os
import time
from collector.baseCollector import BaseCollector
from pathlib import Path

class BashHistoryCollector(BaseCollector):
    def __init__(self, logger, path=None):
        super().__init__(logger)
        #self.path = path or os.path.expanduser("~/.bash_history")
        self.path = path or str(Path.home() / "OneDrive - Eurosystem SPA/Desktop/stage/sandbox/generated_log_2026-05-04T07_05_53.298Z.txt")

    def collect(self):
        self.logger.debug(f"Tailing history file: {self.path}")

        with open(self.path, "r") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                yield self.parse(line.strip())

    def parse(self, raw):
        return {
            "timestamp": time.time(),
            "source": "bash",
            "event_type": "command",
            "message": raw,
            "data": {"command": raw}
        }