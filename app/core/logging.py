import json
import logging
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    """One JSON object per line. json.dumps escapes newlines, so attacker-chosen
    usernames can't forge extra log lines."""

    def format(self, record):
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def setup_logger():
    logger = logging.getLogger("auth")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        # stdout only: the container runtime / process manager collects it.
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


logger = setup_logger()
