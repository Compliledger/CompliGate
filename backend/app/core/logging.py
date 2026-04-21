from __future__ import annotations

import logging


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


def get_logger(name: str = "main") -> logging.Logger:
    return logging.getLogger(name)
