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

    secret_backend: str = "env"
    vault_addr: str | None = None
    vault_token: str | None = None
    vault_namespace: str | None = None
    vault_kv_mount: str = "secret"
    vault_secret_path: str = "agent-ia"
    vault_verify_tls: bool = True
    vault_cache_seconds: int = 60

    ssh_default_user: str = "2com"
    ssh_default_password: str | None = None
    ssh_private_key_path: str | None = None
    ssh_private_key_passphrase: str | None = None
    ssh_allow_agent: bool = True
    ssh_look_for_keys: bool = True
    ssh_default_port: int = 22
    ssh_connect_timeout: int = 15
    ssh_command_timeout: int = 60
    ssh_strict_host_key_checking: bool = True
    ssh_known_hosts_path: str = "~/.ssh/known_hosts"

    ssh_bastion_host: str | None = None
    ssh_bastion_port: int = 22
    ssh_bastion_user: str | None = None
    ssh_bastion_password: str | None = None
    ssh_bastion_private_key_path: str | None = None
    ssh_bastion_private_key_passphrase: str | None = None

    postgres_dsn: str = Field(...)
    redis_url: str = "redis://127.0.0.1:6379/1"

    agent_execution_mode: str = "inline"
    agent_queue_name: str = "agent-ia:jobs"
    agent_result_prefix: str = "agent-ia:result:"
    agent_worker_name: str = "default"
    agent_job_ttl_seconds: int = 86400
    agent_queue_block_seconds: int = 5

    checkmk_api_user: str | None = None
    checkmk_api_secret: str | None = None
    checkmk_webhook_token: str | None = None
    checkmk_webhook_auto_correct: bool = False

    agent_api_token: str | None = None
    agent_default_mode: str = "propose"
    agent_max_rounds: int = 5
    agent_max_commands: int = 20
    agent_min_confidence: int = 70
    agent_playbook_dir: str = str(PROJECT_ROOT / "config" / "playbooks")
    agent_allow_legacy_read_commands: bool = True

    ai_provider: str = "gemini"
    ai_preflight_timeout_seconds: float = Field(default=8.0, ge=1.0, le=60.0)
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"
    groq_api_key: str | None = None
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    openrouter_api_key: str | None = None
    openrouter_model: str = "meta-llama/llama-3.3-70b-instruct:free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_app_name: str = "Agent IA Infra"
    openrouter_site_url: str | None = None
    ollama_model: str = "llama3.2"
    ollama_base_url: str = "http://127.0.0.1:11434"

    # OmniRoute é um gateway: o Agent precisa apenas do token e da URL.
    # A rota/modelo é selecionada no menu, por OMNIROUTE_DEFAULT_ROUTE ou
    # pela lista opcional OMNIROUTE_ROUTES. OMNIROUTE_MODEL permanece como
    # alias legado para instalações anteriores.
    omniroute_api_key: str | None = None
    omniroute_base_url: str = "http://127.0.0.1:20128/v1"
    omniroute_default_route: str = ""
    omniroute_routes: str = ""
    omniroute_model: str = ""

    ai_reviewer_provider: str = "groq"
    ai_reviewer_model: str = ""
    ai_reviewer_required_for_corrections: bool = True
    ai_reviewer_min_confidence: int = 80

    approval_secret: str | None = None
    approval_ttl_minutes: int = 30

    helpdesk_webhook_url: str | None = None
    helpdesk_webhook_token: str | None = None
    helpdesk_publish_automatically: bool = False

    codex_cli_path: str | None = None
    codex_workdir: str | None = None
    codex_home: str | None = None

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
