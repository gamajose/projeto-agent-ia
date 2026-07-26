from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from app.core.policies import EnvironmentType
from app.core.settings import Settings, get_settings
from app.services.dynamic_agent import run_dynamic_investigation
from app.services.persistence import resolve_saved_target
from app.services.playbooks import selected_playbook_ssh_port
from app.services.provider_preflight import require_selected_provider
from app.services.secrets import get_secret
from app.services.ssh import SSHExecutor


@dataclass(frozen=True)
class ResolvedTarget:
    reference: str
    host: str
    port: int
    environment: EnvironmentType
    inventory: dict[str, Any] | None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_target(
    reference: str,
    environment: EnvironmentType = EnvironmentType.UNKNOWN,
    ssh_port: int | None = None,
    *,
    playbook_ssh_port: int | None = None,
    settings: Settings | None = None,
) -> ResolvedTarget:
    settings = settings or get_settings()
    explicit_port = _validate_ssh_port(ssh_port, "informada")
    selected_playbook_port = _validate_ssh_port(playbook_ssh_port, "do playbook")
    default_port = _validate_ssh_port(settings.ssh_default_port, "padrão")
    saved = resolve_saved_target(reference, None if environment == EnvironmentType.UNKNOWN else environment.value)
    if saved:
        resolved_environment = environment
        if resolved_environment == EnvironmentType.UNKNOWN:
            try:
                resolved_environment = EnvironmentType(saved.get("environment") or EnvironmentType.UNKNOWN.value)
            except ValueError:
                resolved_environment = EnvironmentType.UNKNOWN
        saved_port = _validate_ssh_port(saved.get("ssh_port"), "do inventário")
        port = explicit_port or selected_playbook_port or saved_port or default_port
        return ResolvedTarget(reference, str(saved["vpn_ip"]), port, resolved_environment, saved)
    if _is_ip(reference):
        return ResolvedTarget(
            reference,
            reference,
            explicit_port or selected_playbook_port or default_port,
            environment,
            None,
        )
    raise LookupError(f"alvo '{reference}' não existe no inventário; na primeira execução informe o IP VPN")


def _validate_ssh_port(value: Any, source: str) -> int | None:
    if value is None:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"porta SSH {source} é inválida: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"porta SSH {source} deve estar entre 1 e 65535")
    return port


def build_executor(target: ResolvedTarget, *, settings: Settings | None = None) -> SSHExecutor:
    settings = settings or get_settings()
    return SSHExecutor(
        target.host,
        target.port,
        settings.ssh_default_user,
        get_secret("SSH_DEFAULT_PASSWORD", settings.ssh_default_password, settings=settings),
        settings.ssh_connect_timeout,
        private_key_path=settings.ssh_private_key_path,
        private_key_passphrase=get_secret("SSH_PRIVATE_KEY_PASSPHRASE", settings.ssh_private_key_passphrase, settings=settings),
        allow_agent=settings.ssh_allow_agent,
        look_for_keys=settings.ssh_look_for_keys,
        strict_host_key_checking=settings.ssh_strict_host_key_checking,
        known_hosts_path=settings.ssh_known_hosts_path,
        bastion_host=settings.ssh_bastion_host,
        bastion_port=settings.ssh_bastion_port,
        bastion_user=settings.ssh_bastion_user,
        bastion_password=get_secret("SSH_BASTION_PASSWORD", settings.ssh_bastion_password, settings=settings),
        bastion_private_key_path=settings.ssh_bastion_private_key_path,
        bastion_private_key_passphrase=get_secret(
            "SSH_BASTION_PRIVATE_KEY_PASSPHRASE",
            settings.ssh_bastion_private_key_passphrase,
            settings=settings,
        ),
    )


def run_target(
    reference: str,
    objective: str,
    *,
    environment: EnvironmentType = EnvironmentType.UNKNOWN,
    mode: str = "propose",
    approve: bool = False,
    ssh_port: int | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    require_selected_provider(settings)
    playbook_ssh_port, _ = selected_playbook_ssh_port(
        objective.strip() or "validar a saúde geral do servidor"
    )
    target = resolve_target(
        reference,
        environment,
        ssh_port,
        playbook_ssh_port=playbook_ssh_port,
        settings=settings,
    )
    executor = build_executor(target, settings=settings)
    try:
        executor.connect()
        return run_dynamic_investigation(
            executor=executor,
            target=reference,
            context=objective,
            environment=target.environment,
            mode=mode,
            approve=approve,
        )
    finally:
        executor.close()
