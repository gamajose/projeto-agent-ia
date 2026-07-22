from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"

    ssh_default_user: str = "2com"
    ssh_default_password: str | None = None
    ssh_default_port: int = 22
    ssh_connect_timeout: int = 15
    ssh_command_timeout: int = 60

    postgres_dsn: str = Field(...)
    redis_url: str = "redis://127.0.0.1:6379/1"

    checkmk_api_user: str | None = None
    checkmk_api_secret: str | None = None
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.5-flash"

    recurrence_warning_count: int = 2
    recurrence_warning_days: int = 7
    recurrence_critical_count: int = 4
    recurrence_critical_days: int = 30


@lru_cache
def get_settings() -> Settings:
    return Settings()
