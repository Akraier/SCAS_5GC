# logger.py
import logging
import sys

def setup_logger(verbose=False, log_file=None):
    """Setup the root logger."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid adding handlers multiple times
    if logger.hasHandlers():
        return logger

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('[%(levelname)s] %(asctime)s | %(name)s | %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    plain_logger = logging.getLogger("plain")
    plain_logger.setLevel(logging.INFO)
    plain_logger.propagate = False
    if not plain_logger.hasHandlers():
        plain_handler = logging.StreamHandler(sys.stdout)
        plain_handler.setFormatter(logging.Formatter('%(message)s'))  # No timestamp, no level
        plain_logger.addHandler(plain_handler)
        if log_file:
            plain_file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            plain_file_handler.setFormatter(logging.Formatter('%(message)s'))
            plain_logger.addHandler(plain_file_handler)
    return logger
