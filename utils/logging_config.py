"""
utils/logging_config.py
───────────────────────
Structured logging setup supporting JSON and human-readable text formats.
Injects a correlation_id into every log record via a contextvars-based filter.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import time
import uuid
from logging import LogRecord

# ── Correlation-ID context variable ─────────────────────────────────────────

correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)


def new_correlation_id() -> str:
    """Generate a fresh correlation ID and store it in context."""
    cid = str(uuid.uuid4())
    correlation_id_var.set(cid)
    return cid


def get_correlation_id() -> str:
    return correlation_id_var.get()


# ── Filters ──────────────────────────────────────────────────────────────────

class CorrelationIDFilter(logging.Filter):
    """Injects correlation_id into every LogRecord."""

    def filter(self, record: LogRecord) -> bool:
        record.correlation_id = correlation_id_var.get() or "-"
        return True


# ── Formatters ────────────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    RESERVED = {"msg", "args", "exc_info", "exc_text", "stack_info", "message"}

    def format(self, record: LogRecord) -> str:
        # Let the base class handle exception text etc.
        record.message = record.getMessage()
        if record.exc_info:
            record.exc_text = self.formatException(record.exc_info)

        payload: dict = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", "-"),
            "message": record.message,
            "module": record.module,
            "lineno": record.lineno,
        }

        # Append any extra key=value pairs attached by the caller
        for key, val in record.__dict__.items():
            if (
                not key.startswith("_")
                and key not in self.RESERVED
                and key
                not in {
                    "name", "levelname", "levelno", "pathname", "filename",
                    "module", "exc_info", "exc_text", "stack_info", "lineno",
                    "funcName", "created", "msecs", "relativeCreated",
                    "thread", "threadName", "processName", "process",
                    "message", "correlation_id", "taskName",
                }
            ):
                payload[key] = val

        if record.exc_text:
            payload["exception"] = record.exc_text

        return json.dumps(payload, default=str)


TEXT_FORMAT = (
    "%(asctime)s [%(levelname)-8s] %(name)s "
    "[cid=%(correlation_id)s] %(message)s"
)


# ── Setup function ────────────────────────────────────────────────────────────

def setup_logging() -> None:
    """
    Configure the root logger based on LOG_LEVEL and LOG_FORMAT env vars.
    Call once at application startup.
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    fmt = os.environ.get("LOG_FORMAT", "json").lower()

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(CorrelationIDFilter())

    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))

    root = logging.getLogger()
    root.setLevel(level)
    # Remove any default handlers that may have been attached
    root.handlers.clear()
    root.addHandler(handler)

    # Quieten noisy third-party libraries
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
