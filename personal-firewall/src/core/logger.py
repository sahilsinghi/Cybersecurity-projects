import logging
from pathlib import Path

def setup_logger(name="pfw", log_file="data/logs/traffic.log"):
    Path("data/logs").mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)

    # prevent duplicate handlers if setup_logger() is called twice
    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger
