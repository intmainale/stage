class BaseCollector:
    def __init__(self, logger):
        self.logger = logger

    def collect(self):
        raise NotImplementedError

    def parse(self, raw):
        raise NotImplementedError