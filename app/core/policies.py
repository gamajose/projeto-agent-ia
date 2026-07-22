from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class EnvironmentType(StrEnum):
    PRODUCTION = "production"
    STANDBY = "standby"
    MONITORING = "monitoring"
    UNKNOWN = "unknown"


class ActionType(StrEnum):
    READ_ONLY = "read_only"
    SERVICE_ADJUSTMENT = "service_adjustment"
    OMD_ADJUSTMENT = "omd_adjustment"
    CONTAINER_ADJUSTMENT = "container_adjustment"
    DESTRUCTIVE = "destructive"
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

# Stop isolado continua proibido. Stop só é permitido quando o mesmo comando inicia
# imediatamente o mesmo recurso na sequência.
PAIRED_SERVICE_STOP_START_RE = re.compile(
    r"^(?:sudo\s+)?systemctl\s+stop\s+([A-Za-z0-9_.@:-]+)\s*&&\s*(?:sudo\s+)?systemctl\s+start\s+\1$",
    re.I,
)
PAIRED_LEGACY_STOP_START_RE = re.compile(
    r"^(?:sudo\s+)?service\s+([A-Za-z0-9_.@:-]+)\s+stop\s*&&\s*(?:sudo\s+)?service\s+\1\s+start$",
    re.I,
)
PAIRED_DOCKER_STOP_START_RE = re.compile(
    r"^(?:sudo\s+)?docker\s+stop\s+([A-Za-z0-9_.-]+)\s*&&\s*(?:sudo\s+)?docker\s+start\s+\1$",
    re.I,
)
PAIRED_OMD_STOP_START_RE = re.compile(
    r"^(?:sudo\s+)?docker\s+exec\s+([A-Za-z0-9_.-]+)\s+omd\s+stop\s+([A-Za-z0-9_-]+)\s*&&\s*"
    r"(?:sudo\s+)?docker\s+exec\s+\1\s+omd\s+start\s+\2$",
    re.I,
)

DESTRUCTIVE_RE = re.compile(
    r"(^|[;&|]\s*)(rm\s|rmdir\s|unlink\s|truncate\s|dd\s|mkfs\b|wipefs\b|"
    r"systemctl\s+(stop|disable|mask)\b|service\s+\S+\s+stop\b|"
    r"docker\s+(stop|kill|rm|rmi|prune)\b|omd\s+(stop|rm|remove)\b|"
    r"dnf\s+remove\b|yum\s+remove\b|rpm\s+-e\b)",
    re.I,
)
CONTAINER_ADJUST_RE = re.compile(r"\bdocker\s+(start|restart)\b", re.I)
OMD_ADJUST_RE = re.compile(r"\bomd\s+(start|restart)\b", re.I)
SERVICE_ADJUST_RE = re.compile(r"\b(systemctl\s+(start|restart|reload|enable)|service\s+\S+\s+(start|restart|reload))\b", re.I)


def classify_command(command: str) -> ActionType:
    command = command.strip()
    if REBOOT_RE.search(command):
        return ActionType.HOST_REBOOT
    if DB_CLIENT_RE.search(command):
        return ActionType.DATABASE_ACCESS
    if PAIRED_SERVICE_STOP_START_RE.fullmatch(command) or PAIRED_LEGACY_STOP_START_RE.fullmatch(command):
        return ActionType.SERVICE_ADJUSTMENT
    if PAIRED_DOCKER_STOP_START_RE.fullmatch(command):
        return ActionType.CONTAINER_ADJUSTMENT
    if PAIRED_OMD_STOP_START_RE.fullmatch(command):
        return ActionType.OMD_ADJUSTMENT
    if DESTRUCTIVE_RE.search(command):
        return ActionType.DESTRUCTIVE
    if CONTAINER_ADJUST_RE.search(command):
        return ActionType.CONTAINER_ADJUSTMENT
    if OMD_ADJUST_RE.search(command):
        return ActionType.OMD_ADJUSTMENT
    if SERVICE_ADJUST_RE.search(command):
        return ActionType.SERVICE_ADJUSTMENT
    return ActionType.READ_ONLY


def evaluate_action(action: ActionType, environment: EnvironmentType) -> PolicyDecision:
    if action == ActionType.DATABASE_ACCESS:
        return PolicyDecision(False, False, "Acesso a banco de dados do cliente é proibido.", "CUSTOMER_DATABASE_ACCESS_DENIED")
    if action == ActionType.HOST_REBOOT:
        return PolicyDecision(False, False, "Reboot é proibido em todos os ambientes.", "HOST_REBOOT_DENIED")
    if action == ActionType.DESTRUCTIVE:
        return PolicyDecision(False, True, "Remoção, exclusão, desinstalação ou parada isolada exige autorização específica.", "DESTRUCTIVE_ACTION_DENIED")
    if action in {ActionType.SERVICE_ADJUSTMENT, ActionType.CONTAINER_ADJUSTMENT, ActionType.OMD_ADJUSTMENT}:
        return PolicyDecision(True, False, "Ajuste operacional autorizado, com validação obrigatória após a execução.", "SAFE_ADJUSTMENT_ALLOWED")
    return PolicyDecision(True, False, "Comando somente leitura permitido.", "READ_ONLY_ALLOWED")
