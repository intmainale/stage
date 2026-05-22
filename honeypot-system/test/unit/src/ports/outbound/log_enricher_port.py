from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import EnrichableEvent


class DummyEnricher(LogEnricher):
    def enrich(self, entry: EnrichableEvent):
        super().enrich(entry)
        return entry


def test_log_enricher_base_enrich_is_callable():
    enricher = DummyEnricher()
    entry = EnrichableEvent(ip="1.1.1.1")
    assert enricher.enrich(entry) is entry
