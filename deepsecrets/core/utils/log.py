import logging
import multiprocessing
from typing import List
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


def get_error_list() -> List[str]:
    if logger.hasHandlers() is False:
        return []

    for handler in logger.handlers:
        if not isinstance(handler, ErrorListHandler):
            continue

        return handler.records
    return []


logger = build_logger()
