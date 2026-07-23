from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CorrectionDecision:
    allowed: bool
    reason: str
    action_type: str | None = None


ABSOLUTELY_FORBIDDEN = (
    " rm ", "rm -", "unlink ", "rmdir ", "delete ", "truncate ",
    "shutdown", "poweroff", "halt", "reboot", "init 0", "init 6",
    "mkfs", "fdisk", "parted", "dd if=", "wipefs", "lvremove", "vgremove", "pvremove",
    "chmod ", "chown ", "userdel", "useradd", "usermod", "passwd", "groupdel", "groupadd",
    "systemctl stop", "service stop", "docker stop", "docker kill", "docker rm", "docker rmi",
    "docker restart", "docker start", "docker compose", "podman stop", "podman rm", "kubectl delete",
    "dnf ", "yum ", "apt ", "apt-get ", "rpm -e", "pip install", "npm install",
    "iptables ", "nft ", "firewall-cmd", "ufw ",
    "drop database", "drop table", "delete from", "truncate table", "alter table", "update ", "insert into",
    "sed -i", "tee ", "echo ", "cat >", ">", ">>", "curl |", "wget |", "bash -c", "sh -c",
    "kill ", "pkill", "killall", "crontab -r",
)

PROTECTED_UNIT_TERMS = (
    "oracle", "mysql", "mariadb", "postgres", "postgresql", "mongodb", "mongod", "redis",
    "sqlserver", "mssql", "db2", "database", "listener", "asm", "dataguard", "kafka", "rabbitmq",
    "docker", "containerd", "podman", "kubelet", "kubernetes",
)

ALLOWED_SYSTEMD_UNITS = (
    re.compile(r"^(?:check-mk-agent|check_mk|cmk-agent-ctl|xinetd|snmpd|bsnmpd)(?:\.service|\.socket)?$", re.IGNORECASE),
)

ALLOWED_OMD_SERVICES = {
    "automation-helper", "agent-receiver", "apache", "crontab", "mkeventd", "nagios",
    "npcd", "redis", "rrdcached", "ui-job-scheduler", "xinetd",
}

SYSTEMCTL_ACTION = re.compile(r"^systemctl\s+(start|restart|reload|enable|enable\s+--now)\s+([A-Za-z0-9_.@:-]+)$", re.IGNORECASE)
SERVICE_ACTION = re.compile(r"^service\s+([A-Za-z0-9_.@:-]+)\s+(start|restart|reload)$", re.IGNORECASE)
OMD_DIRECT = re.compile(r"^omd\s+(start|restart)\s+([A-Za-z0-9_.@:-]+)$", re.IGNORECASE)
OMD_DOCKER = re.compile(
    r"^docker\s+exec\s+[A-Za-z0-9_.-]+\s+su\s+-\s+[A-Za-z0-9_-]+\s+-c\s+['\"]omd\s+(start|restart)\s+([A-Za-z0-9_.@:-]+)['\"]$",
    re.IGNORECASE,
)


def _contains_forbidden(command: str) -> str | None:
    normalized = f" {command.strip().casefold()} "
    for token in ABSOLUTELY_FORBIDDEN:
        if token in normalized:
            return token.strip()
    return None


def _protected_unit(unit: str) -> bool:
    lowered = unit.casefold()
    return any(term in lowered for term in PROTECTED_UNIT_TERMS)


def _allowed_system_unit(unit: str) -> bool:
    return any(pattern.fullmatch(unit) for pattern in ALLOWED_SYSTEMD_UNITS)


def validate_correction(command: str) -> CorrectionDecision:
    """Autoriza somente recuperação controlada de componentes de monitoramento.

    A IA nunca pode parar, remover, apagar, editar, instalar, reiniciar host,
    manipular banco de dados ou controlar o ciclo de vida de containers.
    """
    stripped = command.strip()
    if not stripped:
        return CorrectionDecision(False, "comando vazio")

    forbidden = _contains_forbidden(stripped)
    if forbidden:
        return CorrectionDecision(False, f"operação proibida pela política: {forbidden}")

    match = SYSTEMCTL_ACTION.fullmatch(stripped)
    if match:
        action, unit = match.groups()
        if _protected_unit(unit):
            return CorrectionDecision(False, "serviço protegido não pode ser alterado automaticamente")
        if not _allowed_system_unit(unit):
            return CorrectionDecision(False, "somente unidades autorizadas de monitoramento podem ser recuperadas")
        return CorrectionDecision(True, "unidade autorizada de monitoramento", f"systemctl_{action.replace(' ', '_')}")

    match = SERVICE_ACTION.fullmatch(stripped)
    if match:
        unit, action = match.groups()
        if _protected_unit(unit):
            return CorrectionDecision(False, "serviço protegido não pode ser alterado automaticamente")
        if not _allowed_system_unit(unit):
            return CorrectionDecision(False, "somente serviços autorizados de monitoramento podem ser recuperados")
        return CorrectionDecision(True, "serviço autorizado de monitoramento", f"service_{action}")

    match = OMD_DIRECT.fullmatch(stripped) or OMD_DOCKER.fullmatch(stripped)
    if match:
        action, service = match.groups()
        if service.casefold() not in ALLOWED_OMD_SERVICES:
            return CorrectionDecision(False, "serviço OMD não está na lista de recuperação automática")
        return CorrectionDecision(True, "serviço OMD autorizado", f"omd_{action}")

    return CorrectionDecision(False, "comando fora da política restrita de correção automática")
