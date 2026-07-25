from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from app.core.policies import EnvironmentType
from app.core.settings import Settings, get_settings
from app.services.dynamic_agent import run_dynamic_investigation
from app.services.persistence import resolve_saved_target
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
    settings: Settings | None = None,
) -> ResolvedTarget:
    settings = settings or get_settings()
    saved = resolve_saved_target(reference, None if environment == EnvironmentType.UNKNOWN else environment.value)
    if saved:
        resolved_environment = environment
        if resolved_environment == EnvironmentType.UNKNOWN:
            try:
                resolved_environment = EnvironmentType(saved.get("environment") or EnvironmentType.UNKNOWN.value)
            except ValueError:
                resolved_environment = EnvironmentType.UNKNOWN
        return ResolvedTarget(reference, str(saved["vpn_ip"]), int(saved["ssh_port"]), resolved_environment, saved)
    if _is_ip(reference):
        return ResolvedTarget(reference, reference, int(ssh_port or settings.ssh_default_port), environment, None)
    raise LookupError(f"alvo '{reference}' não existe no inventário; na primeira execução informe o IP VPN")


def build_executor(target: ResolvedTarget, *, settings: Settings | None = None) -> SSHExecutor:
    settings = settings or get_settings()
    return SSHExecutor(
        target.host,
        target.port,
        settings.ssh_default_user,
        settings.ssh_default_password,
        settings.ssh_connect_timeout,
        private_key_path=settings.ssh_private_key_path,
        private_key_passphrase=settings.ssh_private_key_passphrase,
        allow_agent=settings.ssh_allow_agent,
        look_for_keys=settings.ssh_look_for_keys,
        strict_host_key_checking=settings.ssh_strict_host_key_checking,
        known_hosts_path=settings.ssh_known_hosts_path,
        bastion_host=settings.ssh_bastion_host,
        bastion_port=settings.ssh_bastion_port,
        bastion_user=settings.ssh_bastion_user,
        bastion_password=settings.ssh_bastion_password,
        bastion_private_key_path=settings.ssh_bastion_private_key_path,
        bastion_private_key_passphrase=settings.ssh_bastion_private_key_passphrase,
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
    target = resolve_target(reference, environment, ssh_port, settings=settings)
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
