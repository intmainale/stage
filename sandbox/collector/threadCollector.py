import threading

class CollectorThread(threading.Thread):
    def __init__(self, collector, out_queue, logger):
        super().__init__(daemon=True)
        self.collector = collector
        self.queue = out_queue
        self.logger = logger

    def run(self):
        self.logger.info(f"Starting {self.collector.__class__.__name__}")

        try:
            for event in self.collector.collect():
                if event:
                    self.queue.put(event)

        except Exception as e:
            self.logger.error(f"{self.collector.__class__.__name__} crashed: {e}")