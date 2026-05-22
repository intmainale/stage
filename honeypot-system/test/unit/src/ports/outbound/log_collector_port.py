from src.ports.outbound.log_collector_port import LogCollector


class DummyCollector(LogCollector):
    def collect(self):
        super().collect()
        return iter([])


def test_log_collector_base_collect_is_callable():
    collector = DummyCollector()
    assert list(collector.collect()) == []
