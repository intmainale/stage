import os
import time
from collector.baseCollector import BaseCollector
from pathlib import Path

class BashHistoryCollector(BaseCollector):
    def __init__(self, logger, path=None):
        super().__init__(logger)
        self.path = path or os.path.expanduser("~/.bash_history")
        self.logger.debug(f"Initialized BashHistoryCollector with path: {self.path}")
        """base_dir = Path(os.getenv("BASE_DIR", "/app")).resolve()

        self.path = base_dir / "collector/ex_log.txt"
        """

    def collect(self):
        self.logger.debug(f"Tailing history file: {self.path}")

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
                "source": "bash",
                "message": raw.strip()
            }
        except Exception as e:
            self.logger.error(f"bash parse error: {e}")
            return None