"""
Settings loader for orchestrator config (TOML-based).
Centralizes MulVAL orchestration configuration.
"""

import toml

from pydantic import SecretStr, FilePath

from ..models.config.orchestrator_config import Orchestrator

from .logger import Logger


class Settings:
    """
    Loads and manages orchestrator configuration from TOML.
    """

    def __init__(self, toml_path: FilePath) -> None:
        """
        Init and load config models from TOML file.
        Args:
            toml_path (FilePath): Path to TOML config.
        Raises:
            Exception: On config load failure.
        """
        self.ORCHESTRATOR = Orchestrator()
        self._log = Logger.get_logger()
        self._config_models = {
            "ORCHESTRATOR": self.ORCHESTRATOR,
        }

        self._load_configuration_from_file(toml_path)

    def _load_configuration_from_file(self, toml_path: FilePath) -> None:
        """
        Load config from TOML file and wrap secrets.
        Args:
            toml_path (FilePath): Path to TOML config.
        Raises:
            Exception: On TOML parse or model error.
        """
        with open(toml_path, "r", encoding="utf-8") as config_file:
            toml_data = toml.load(config_file)

        for model_key, model_obj in self._config_models.items():
            config_section = toml_data.get(model_key)
            if not config_section:
                self._log.warning(f"Missing TOML section: {model_key}")
                continue

            for field_key, field_value in config_section.items():
                field_meta = type(model_obj).model_fields.get(field_key)

                if field_meta:
                    field_annotation = str(field_meta.annotation)
                    if "SecretStr" in field_annotation:
                        config_section[field_key] = SecretStr(field_value)
            try:
                setattr(self, model_key, model_obj.model_copy(update=config_section))
                self._log.debug(f"Successfully loaded config: {model_key}")
            except Exception as config_error:
                self._log.error(
                    f"Failed to load {model_key}: {config_error}", exc_info=True
                )
