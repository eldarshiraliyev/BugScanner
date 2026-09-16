"""
Structured logging via structlog.

Every log line is emitted as JSON alongside the Rich console output.
Set BUGSCANNER_LOG_JSON=1 to enable JSON logs (default).
Set BUGSCANNER_LOG_FILE=/path/to/file.log to also write to a file.
"""

import os
import logging
import sys
from pathlib import Path

try:
    import structlog
    _HAS_STRUCTLOG = True
except ImportError:
    _HAS_STRUCTLOG = False


_configured = False


def configure_logging():
    global _configured
    if _configured:
        return
    _configured = True

    log_level = os.getenv("BUGSCANNER_LOG_LEVEL", "INFO").upper()
    log_file = os.getenv("BUGSCANNER_LOG_FILE")

    if not _HAS_STRUCTLOG:
        # Fallback: basic stdlib logging
        handlers = [logging.StreamHandler(sys.stderr)]
        if log_file:
            handlers.append(logging.FileHandler(log_file))
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            handlers=handlers,
        )
        return

    # ── structlog setup ──
    timestamper = structlog.processors.TimeStamper(fmt="iso")

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        timestamper,
    ]

    if log_file:
        # JSON to file
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.processors.JSONRenderer(),
                foreign_pre_chain=shared_processors,
            )
        )
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_level, logging.INFO))
        root_logger.addHandler(file_handler)

    structlog.configure(
        processors=shared_processors + [
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "bugscanner"):
    configure_logging()
    if _HAS_STRUCTLOG:
        return structlog.get_logger(name)
    return logging.getLogger(name)