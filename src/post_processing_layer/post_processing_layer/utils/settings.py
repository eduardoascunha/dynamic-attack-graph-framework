"""
Settings loader for the post-processing layer (TOML-based).

Loads [DATABASE] and [POST_PROCESSING] sections from a TOML configuration
file and populates the corresponding Pydantic model instances.
"""

import toml

from pydantic import SecretStr, FilePath

from ..models.config.database_config import Database
from ..models.config.post_processing_config import PostProcessing
from .logger import Logger


class Settings:
    """
    Loads and exposes database and post-processing configuration from TOML.

    Attributes:
        DATABASE:        Populated ``Database`` model with connection settings.
        POST_PROCESSING: Populated ``PostProcessing`` model with pipeline settings.
    """

    def __init__(self, toml_path: FilePath) -> None:
        self.DATABASE = Database()
        self.POST_PROCESSING = PostProcessing()
        self._log = Logger.get_logger()
        self._config_models: dict = {
            "DATABASE": self.DATABASE,
            "POST_PROCESSING": self.POST_PROCESSING,
        }
        self._load_configuration_from_file(toml_path)

    def _load_configuration_from_file(self, toml_path: FilePath) -> None:
        with open(toml_path, "r", encoding="utf-8") as config_file:
            toml_data = toml.load(config_file)

        for model_key, model_obj in self._config_models.items():
            config_section = toml_data.get(model_key)
            if not config_section:
                self._log.warning("Missing TOML section: %s", model_key)
                continue

            for field_key, field_value in config_section.items():
                field_meta = type(model_obj).model_fields.get(field_key)
                if field_meta and "SecretStr" in str(field_meta.annotation):
                    config_section[field_key] = SecretStr(field_value)

            try:
                updated = type(model_obj)(
                    **{**model_obj.model_dump(), **config_section}
                )
                setattr(self, model_key, updated)
                self._config_models[model_key] = updated
                self._log.debug("Loaded config section: %s", model_key)
            except Exception as exc:
                self._log.error(
                    "Failed to load config section '%s': %s", model_key, exc
                )
                raise
