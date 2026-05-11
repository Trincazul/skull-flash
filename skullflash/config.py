"""Settings loaded from YAML files and environment variables."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

import yaml
from pydantic import field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict


class _YamlSource(PydanticBaseSettingsSource):
    """Merge one or more YAML files into a flat settings dict."""

    def __init__(self, settings_cls: Type[BaseSettings], paths: List[Path]) -> None:
        super().__init__(settings_cls)
        self._data: Dict[str, Any] = {}
        for p in paths:
            if p.exists():
                with open(p) as fh:
                    self._data.update(yaml.safe_load(fh) or {})

    def get_field_value(self, field: Any, field_name: str) -> Tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> Dict[str, Any]:
        return {k: v for k, v in self._data.items() if v is not None}


class SkullFlashConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKULLFLASH_")

    # Scan limits
    scan_timeout: int = 30
    request_timeout: int = 10
    max_concurrent_tasks: int = 50
    rate_limit_per_second: int = 10

    # Optional API keys (never hardcoded — env or config file only)
    nvd_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None

    # Scope / safety
    allowed_targets: List[str] = []
    blocked_targets: List[str] = []

    # Output
    default_output_dir: Path = Path("./skull-flash-reports")
    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        valid = {"TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v.upper()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            _YamlSource(
                settings_cls,
                [
                    Path("config/default.yaml"),
                    Path.home() / ".skullflash" / "config.yaml",
                ],
            ),
        )


def load_config() -> SkullFlashConfig:
    """Return a fully-loaded SkullFlashConfig instance."""
    return SkullFlashConfig()
