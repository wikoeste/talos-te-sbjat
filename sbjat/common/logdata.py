# create a log of the tools actions for review
# due to the cron tab automation
import logging
import os
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

# write to users home directory
log_dir = Path(os.getenv("SBJAT_LOG_DIR", str(Path.home() / "logs")))

logger = logging.getLogger("sbjat")
logger.setLevel(logging.INFO)
if not logger.handlers:
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_dir / "talos-te-sbjat-err.log",
            maxBytes=5_000_000,
            backupCount=3,
        )
    except OSError:
        # Logging should never prevent the automation itself from starting.
        fallback_dir = Path(tempfile.gettempdir()) / "sbjat-logs"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            fallback_dir / "talos-te-sbjat-err.log",
            maxBytes=5_000_000,
            backupCount=3,
        )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s:%(name)s:%(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
