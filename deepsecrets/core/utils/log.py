import logging
import multiprocessing
from deepsecrets import MODULE_NAME


def set_logging_level(logger: logging.Logger, level: int) -> None:
    logger.setLevel(level)
    for handler in logger.handlers:
        if isinstance(handler, type(logging.StreamHandler())):
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter('DS-%(levelname)s: %(message)s'))

    if level == logging.DEBUG and multiprocessing.current_process().name == 'MainProcess':
        #logger.debug('Debug logging enabled')
        pass

    

def build_logger(level: int = logging.INFO) -> logging.Logger:
    logging.basicConfig(format=' %(message)s', level=level)
    logger = logging.getLogger(MODULE_NAME)
    set_logging_level(logger=logger, level=level)
    return logger


logger = build_logger()