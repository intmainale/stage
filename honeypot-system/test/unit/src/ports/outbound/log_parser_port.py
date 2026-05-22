from src.ports.outbound.log_parser_port import LogParser

from src.domain.models.event import Event


class DummyParser(LogParser):
    def parse(self, raw_line: str):
        super().parse(raw_line)
        return Event()


def test_log_parser_base_parse_is_callable():
    parser = DummyParser()
    assert parser.parse("test") is not None
