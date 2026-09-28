"""
Singleton logger utility for the app.
Supports INI config with security checks.
"""

import logging
import logging.config
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar


class Logger:
    """
    Singleton logger manager.
    Use configure() to set up logging, get_logger() to retrieve the logger.
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
        Configure logger from INI config file.
        
        Raises:
            RuntimeError: If already configured.
            FileNotFoundError: If config file not found.
            ValueError: If config file is not .ini format.
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
        name: str = "orchestrator_service",
    ) -> logging.Logger:
        """
        Get the singleton logger instance.
        
        Raises:
            RuntimeError: If logger not configured.
        """
        if not cls.__configured:
            raise RuntimeError("Logger not configured. Call configure() first.")

        if cls.__instance is None:
            logger = logging.getLogger(name or "orchestrator_service")
            logger.propagate = False
            cls.__instance = logger

        return cls.__instance
