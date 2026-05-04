from collector.logger import Log
from collector.MQTTPublisher import MQTTPublisher
from collector.auditdCollector import AuditdCollector
from collector.bashHistoryCollector import BashHistoryCollector
from collector.journalCollector import JournalctlCollector
from collector.normalizer import Normalizer
from collector.orchestrator import LogPipeline
from collector.topicRouter import TopicRouter


if __name__ == "__main__":
    logger = Log()

    pipeline = LogPipeline(
        collectors=[
            BashHistoryCollector(logger),
            #JournalctlCollector(logger),
            #AuditdCollector(logger)
        ],
        normalizer=Normalizer(),
        router=TopicRouter(),
        publisher=MQTTPublisher(logger),
        logger=logger
    )

    pipeline.run()