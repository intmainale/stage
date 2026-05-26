import pytest

from src.application.application import Application
from src.application.pipeline import Pipeline
from src.domain.exceptions.domain_exceptions import PipelineError


class FakeThread:
    def __init__(self, collector=None, pipeline=None, stop_event=None):
        self.started = False
        self.joined = False
        self.name = "FakeThread"
        self._alive = False

    def start(self):
        self.started = True
        self._alive = True

    def join(self, timeout=None):
        self.joined = True
        self._alive = False

    def is_alive(self):
        return self._alive


def test_build_pipeline_raises_when_pipeline_is_empty(mocker):
    app = Application({}, {}, [], [])
    empty_pipeline = Pipeline()

    mocker.patch("src.application.application.PipelineBuilder.build", return_value=empty_pipeline)
    with pytest.raises(PipelineError):
        app.build_pipeline()


def test_start_and_stop_pipeline_starts_one_collector_thread(mocker):
    app = Application({}, {}, [], [])
    app._pipeline = Pipeline()
    app._pipeline.parsers = {"apache": object()}
    app._pipeline.collectors = [object()]
    app._pipeline.enrichers = []
    app._pipeline.publishers = []

    mocker.patch("src.application.application.CollectorThread", FakeThread)
    app.start_pipeline()
    assert len(app._threads) == 1
    assert app._threads[0].started is True

    app.stop_pipeline()
    assert app._threads == []
    assert app._stop_event.is_set()