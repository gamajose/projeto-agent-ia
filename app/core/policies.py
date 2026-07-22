from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class EnvironmentType(StrEnum):
    PRODUCTION = "production"
    STANDBY = "standby"
    MONITORING = "monitoring"
    TRAINING = "training"
    UNKNOWN = "unknown"


class ActionType(StrEnum):
    READ_ONLY = "read_only"
    SERVICE_RESTART = "service_restart"
    OMD_RESTART = "omd_restart"
    CONTAINER_RESTART = "container_restart"
    HOST_REBOOT = "host_reboot"
    DATABASE_ACCESS = "database_access"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    policy_code: str


REBOOT_RE = re.compile(r"(^|[;&|]\s*)(reboot|shutdown|poweroff|halt|init\s+6|systemctl\s+reboot)\b", re.I)
DB_CLIENT_RE = re.compile(r"(^|[;&|]\s*)(sqlplus|rman|psql|mysql|mariadb|sqlcmd|mongosh?|redis-cli)\b", re.I)
CONTAINER_RESTART_RE = re.compile(r"\bdocker\s+(restart|stop|kill)\b", re.I)
OMD_RESTART_RE = re.compile(r"\bomd\s+(restart|stop)\b", re.I)
SERVICE_RESTART_RE = re.compile(r"\b(systemctl|service)\s+(restart|stop)\b", re.I)


def classify_command(command: str) -> ActionType:
    if REBOOT_RE.search(command):
        return ActionType.HOST_REBOOT
    if DB_CLIENT_RE.search(command):
        return ActionType.DATABASE_ACCESS
    if CONTAINER_RESTART_RE.search(command):
        return ActionType.CONTAINER_RESTART
    if OMD_RESTART_RE.search(command):
        return ActionType.OMD_RESTART
    if SERVICE_RESTART_RE.search(command):
        return ActionType.SERVICE_RESTART
    return ActionType.READ_ONLY


def evaluate_action(action: ActionType, environment: EnvironmentType) -> PolicyDecision:
    if action == ActionType.DATABASE_ACCESS:
        return PolicyDecision(False, False, "Acesso a banco de dados de cliente é proibido.", "CUSTOMER_DATABASE_ACCESS_DENIED")

    if action == ActionType.HOST_REBOOT:
        if environment != EnvironmentType.TRAINING:
            return PolicyDecision(False, False, "Reboot proibido em produção, standby, monitoramento ou ambiente desconhecido.", "HOST_REBOOT_DENIED")
        return PolicyDecision(True, True, "Reboot permitido apenas em treinamento e com aprovação explícita.", "HOST_REBOOT_APPROVAL_REQUIRED")

    if action in {ActionType.CONTAINER_RESTART, ActionType.OMD_RESTART}:
        return PolicyDecision(True, True, "Ação com impacto operacional exige aprovação explícita.", "IMPACT_ACTION_APPROVAL_REQUIRED")

    if action == ActionType.SERVICE_RESTART:
        return PolicyDecision(True, True, "Restart de serviço exige aprovação explícita nesta primeira versão.", "SERVICE_RESTART_APPROVAL_REQUIRED")

    return PolicyDecision(True, False, "Comando somente leitura permitido.", "READ_ONLY_ALLOWED")
