from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    log_level: str = "INFO"

    ssh_default_user: str = "2com"
    ssh_default_password: str | None = None
    ssh_private_key_path: str | None = None
    ssh_private_key_passphrase: str | None = None
    ssh_allow_agent: bool = True
    ssh_look_for_keys: bool = True
    ssh_default_port: int = 22
    ssh_connect_timeout: int = 15
    ssh_command_timeout: int = 60

    postgres_dsn: str = Field(...)
    redis_url: str = "redis://127.0.0.1:6379/1"

    checkmk_api_user: str | None = None
    checkmk_api_secret: str | None = None
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"

    recurrence_warning_count: int = 2
    recurrence_warning_days: int = 7
    recurrence_critical_count: int = 4
    recurrence_critical_days: int = 30

    filesystem_warning_percent: int = 80
    filesystem_critical_percent: int = 90
    inode_warning_percent: int = 80
    inode_critical_percent: int = 90
    load_warning_ratio: int = 1
    load_critical_ratio: int = 2
    agent_max_rounds: int = 5
    agent_max_commands: int = 20
    agent_min_confidence: int = 70


@lru_cache
def get_settings() -> Settings:
    return Settings()
