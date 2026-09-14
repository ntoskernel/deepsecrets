import logging
import multiprocessing
from typing import List, Optional
from deepsecrets import MODULE_NAME


class ErrorListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(self.format(record))


def set_logging_level(logger: logging.Logger, level: int) -> None:
    logger.setLevel(level)
    for handler in logger.handlers:
        if isinstance(handler, type(logging.StreamHandler())):
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter('DS-%(levelname)s: %(message)s'))

    if level == logging.DEBUG and multiprocessing.current_process().name == 'MainProcess':
        # logger.debug('Debug logging enabled')
        pass


def build_logger(level: int = logging.INFO) -> logging.Logger:
    logging.basicConfig(format=' %(message)s', level=level)
    logger = logging.getLogger(MODULE_NAME)
    set_logging_level(logger=logger, level=level)
    logger.addHandler(ErrorListHandler())
    return logger


def _error_list_handler() -> Optional[ErrorListHandler]:
    for handler in logger.handlers:
        if isinstance(handler, ErrorListHandler):
            return handler
    return None


def get_error_list() -> List[str]:
    handler = _error_list_handler()
    # a copy: the live list keeps growing in a worker that handles more files
    return list(handler.records) if handler is not None else []


def clear_error_list() -> None:
    handler = _error_list_handler()
    if handler is not None:
        handler.records.clear()


logger = build_logger()
