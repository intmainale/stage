from src.infrastructure.logger import Logger


def test_logger_is_singleton():
    first = Logger.get_instance()
    second = Logger.get_instance()
    assert first is second


def test_logger_methods_do_not_raise():
    logger = Logger.get_instance()
    logger.debug("debug message")
    logger.info("info message")
    logger.warning("warning message")
    logger.error("error message")
    logger.exception("exception message")