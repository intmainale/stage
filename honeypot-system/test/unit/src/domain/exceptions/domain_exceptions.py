import importlib

module = importlib.import_module('src.domain.exceptions.domain_exceptions')


def test_import_module():
    assert module is not None
