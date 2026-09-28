"""
Singleton logger utility for the post-processing layer.
Delegates to Python's logging.config with an INI-file configuration.
"""

import logging
import logging.config

from pathlib import Path
from threading import Lock
from typing import Any, ClassVar


class Logger:
    """
    Singleton logger manager. Call ``configure()`` once at startup,
    then ``get_logger()`` anywhere in the application.
    """

    __instance: ClassVar[logging.Logger | None] = None
    __configured: ClassVar[bool] = False
    __lock: ClassVar[Lock] = Lock()

    @classmethod
    def configure(
        cls,
        config_file: str | Path,
        defaults: dict[str, Any] | None = None,
    ) -> None:
        """
        Configure logging from an INI config file.
        Raises if already configured or the file is missing / not .ini.
        """
        with cls.__lock:
            if cls.__configured:
                raise RuntimeError("Logger has already been configured.")

            path = Path(config_file).resolve()

            if not path.exists():
                raise FileNotFoundError(f"Logging config not found: {path}")

            if path.suffix.lower() != ".ini":
                raise ValueError("Only .ini logging config files are supported.")

            logging.config.fileConfig(
                fname=str(path),
                defaults=defaults or {},
                disable_existing_loggers=False,
                encoding="utf-8",
            )

            cls.__configured = True

    @classmethod
    def get_logger(
        cls,
        name: str = "post_processing_layer",
    ) -> logging.Logger:
        """
        Return the singleton Logger instance. Raises if not yet configured.
        """
        if not cls.__configured:
            raise RuntimeError("Logger not configured. Call configure() first.")

        if cls.__instance is None:
            logger = logging.getLogger(name or "post_processing_layer")
            logger.propagate = False
            cls.__instance = logger

        return cls.__instance
