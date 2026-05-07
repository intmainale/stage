from collector.logger import Log
from collector.MQTTPublisher import MQTTPublisher
from collector.auditdCollector import AuditdCollector
from collector.bashHistoryCollector import BashHistoryCollector
from collector.journalCollector import JournalctlCollector
from collector.normalizer import Normalizer
from collector.orchestrator import LogPipeline
from collector.topicRouter import TopicRouter
from pathlib import Path
import glob

paths = glob.glob("/home/*/.bash_history") #[Path.home() / "OneDrive - Eurosystem SPA/Desktop/stage/honeypot-machine/collector/generated_log_2026-05-04T07_05_53.298Z.txt"] glob.glob("/home/*/.bash_history")
paths.append("/root/.bash_history")

if __name__ == "__main__":
    logger = Log()
    bash_collectors = [
        BashHistoryCollector(logger, path=p)
        for p in paths
    ]

    system_collectors = [
        JournalctlCollector(logger),
        AuditdCollector(logger)
    ]
    
    pipeline = LogPipeline(
        collectors=bash_collectors + system_collectors, #[BashHistoryCollector(logger)],
        normalizer=Normalizer(logger),
        router=TopicRouter(),
        publisher=MQTTPublisher(logger),
        logger=logger
    )

    pipeline.run()