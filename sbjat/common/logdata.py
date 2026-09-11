# create a log of the tools actions for review
# due to the cron tab automation
import logging
import os
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Keep automation logs in one predictable per-user location.
log_dir = Path.home() / "logs"

logger = logging.getLogger("sbjat")
log_level = os.getenv("SBJAT_LOG_LEVEL", "INFO").upper()
logger.setLevel(getattr(logging, log_level, logging.INFO))
logger.propagate = False
if not logger.handlers:
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_dir / "talos-te-sbjat-err.log",
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8",
        )
    except OSError:
        # Logging should never prevent the automation itself from starting.
        fallback_dir = Path(tempfile.gettempdir()) / "sbjat-logs"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            fallback_dir / "talos-te-sbjat-err.log",
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8",
        )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s:%(name)s:%(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
