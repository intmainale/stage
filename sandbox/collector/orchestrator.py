import queue
from collector.threadCollector import CollectorThread

class LogPipeline:
    def __init__(self, collectors, normalizer, router, publisher, logger):
        self.collectors = collectors
        self.normalizer = normalizer
        self.router = router
        self.publisher = publisher
        self.logger = logger

        self.queue = queue.Queue()

    def start_collectors(self):
        self.threads = []

        for c in self.collectors:
            t = CollectorThread(c, self.queue, self.logger)
            t.start()
            self.threads.append(t)

    def process_loop(self):
        self.logger.info("Starting processing loop")

        while True:
            event = self.queue.get()

            event = self.normalizer.normalize(event)
            topic, payload = self.router.route(event)

            if topic:
                self.publisher.publish(topic, payload)

            self.queue.task_done()

    def run(self):
        self.start_collectors()
        self.process_loop()