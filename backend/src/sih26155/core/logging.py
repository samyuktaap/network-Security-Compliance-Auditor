"""
Centralized structured logging configuration for SIH AI Compliance Engine.
"""

from __future__ import annotations

import logging
import os
import sys


def setup_logging(level: str | None = None) -> logging.Logger:
    """
    Configures application-wide logging with uniform formatting, timestamp,
    log level, and module context.
    """
    log_level_name = level or os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    log_format = (
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        if os.getenv("LOG_FORMAT", "standard") == "standard"
        else '{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
    )

    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    # Suppress overly chatty third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("netmiko").setLevel(logging.INFO)

    root_logger = logging.getLogger("sih26155")
    root_logger.setLevel(log_level)
    return root_logger
