import os
from pathlib import Path
import subprocess
import json
import time
from collector.baseCollector import BaseCollector

class JournalctlCollector(BaseCollector):
    def __init__(self, logger, path=None):
        super().__init__(logger)
        #self.path = path or os.path.expanduser("~/.bash_history")
        """base_dir = Path(os.getenv("BASE_DIR", "/app")).resolve()

        self.path = base_dir / "collector/ex_log.txt"
        """
        
    def collect(self):
        self.logger.debug("Collecting journalctl logs")

        cmd = ["journalctl", "-f", "-o", "json"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

        for line in process.stdout:
            yield self.parse(line)
    
    def collect(self):
        self.logger.debug(f"Tailing journald file: {self.path}")

        with open(self.path, "r") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                yield self.parse(line)

    def parse(self, raw):
        try:
            return {
                "source": "journal",
                "message": raw.strip()
            }

        except Exception as e:
            self.logger.error(f"journal parse error: {e}")
            return None