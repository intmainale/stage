import threading

from src.ports.outbound.log_collector_port import LogCollector


class DummyCollector(LogCollector):
    def collect(self, stop_event: threading.Event):
        super().collect(stop_event)
        return iter([])


def test_log_collector_base_collect_is_callable():
    collector = DummyCollector()
    assert list(collector.collect(threading.Event())) == []
