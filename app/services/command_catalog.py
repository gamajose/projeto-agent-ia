from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True)
class CommandSpec:
    name: str
    category: str
    pattern: re.Pattern[str]
    read_only: bool = True
    requires_sudo: bool = False
    timeout: int = 120
    availability_binary: str | None = None


FORBIDDEN_TOKENS = (
    " rm ", "rm -", " reboot", "shutdown", "poweroff", "halt", "mkfs", "fdisk",
    "parted", "dd if=", "chmod ", "chown ", "userdel", "useradd", "passwd",
    "systemctl restart", "systemctl start", "systemctl stop", "service restart",
    "service start", "service stop", "docker restart", "docker start", "docker stop",
    "docker rm", "docker kill", "docker compose up", "docker compose down", ">", ">>",
    "curl |", "wget |", "bash -c", "sh -c", "eval ", "kill ", "pkill", "killall",
)


def _p(expression: str) -> re.Pattern[str]:
    return re.compile(expression, re.IGNORECASE)


CATALOG: tuple[CommandSpec, ...] = (
    CommandSpec("system_basics", "system", _p(r"^(uptime|hostname|hostnamectl|uname|nproc|date|timedatectl|who|w|last)(\s|$)")),
    CommandSpec("cpu_memory", "resources", _p(r"^(free|vmstat|iostat|mpstat|sar|lscpu|lsmem|top|ps)(\s|$)")),
    CommandSpec("filesystem", "filesystem", _p(r"^(df|du|lsblk|blkid|mount|findmnt|stat|find|ls)(\s|$)")),
    CommandSpec("network", "network", _p(r"^(ip|ss|netstat|route|arp|ping|traceroute|tracepath|ethtool|resolvectl|getent|host|dig|nslookup)(\s|$)")),
    CommandSpec("text_read", "generic", _p(r"^(cat|head|tail|grep|awk|sed|cut|sort|uniq|wc)(\s|$)")),
    CommandSpec("logs", "logs", _p(r"^(journalctl|dmesg)(\s|$)"), requires_sudo=True),
    CommandSpec("systemd_read", "service", _p(r"^systemctl\s+(status|is-active|is-enabled|list-units|list-unit-files|show|cat)(\s|$)")),
    CommandSpec("service_read", "service", _p(r"^service\s+[A-Za-z0-9_.@:-]+\s+status$")),
    CommandSpec("docker_read", "container", _p(r"^docker\s+(ps|info|version|inspect|logs|events|stats)(\s|$)"), requires_sudo=True, availability_binary="docker"),
    CommandSpec("docker_exec_read", "monitoring", _p(r"^docker\s+exec\s+[A-Za-z0-9_.-]+\s+(omd\s+(status|sites)|su\s+-\s+[A-Za-z0-9_-]+\s+-c\s+['\"]?(cmk\s+(-D|-d|-vvn|--list-hosts)|omd\s+(status|sites)|tail|grep|ps|cat|ls|df|free|uptime))"), requires_sudo=True, availability_binary="docker"),
    CommandSpec("checkmk_agent", "monitoring", _p(r"^cmk-agent-ctl\s+status(\s|$)"), availability_binary="cmk-agent-ctl"),
    CommandSpec("snmp_read", "network", _p(r"^snmp(get|walk|bulkwalk)(\s|$)"), availability_binary="snmpwalk"),
)


def match_command(command: str) -> CommandSpec | None:
    stripped = command.strip()
    normalized = f" {stripped.casefold()} "
    if not stripped or any(token in normalized for token in FORBIDDEN_TOKENS):
        return None
    first = stripped.split(";", 1)[0].strip()
    return next((spec for spec in CATALOG if spec.pattern.search(first)), None)


def validate_command(command: str) -> tuple[bool, str, CommandSpec | None]:
    spec = match_command(command)
    if spec is None:
        return False, "comando fora do catálogo seguro de investigação", None
    if not spec.read_only:
        return False, "comando não é somente leitura", spec
    return True, "autorizado", spec


def categories() -> Iterable[str]:
    return sorted({spec.category for spec in CATALOG})
