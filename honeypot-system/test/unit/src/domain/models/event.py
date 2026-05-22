import importlib

module = importlib.import_module('src.domain.models.event')


def test_import_module():
    assert module is not None
