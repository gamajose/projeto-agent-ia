from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass
from typing import Any

from app.core.policies import EnvironmentType, environment_allows_correction
from app.services.correction_policy import validate_correction
from app.services.redaction import redact_text
from app.services.ssh import SSHExecutor


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./@:+-]*$")
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


class ToolValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ToolPlan:
    name: str
    category: str
    command: str
    sudo: bool = False
    timeout: int = 120
    correction: bool = False
    preconditions: tuple[str, ...] = ()
    validations: tuple[str, ...] = ()
    rollback_command: str | None = None
    purpose: str = ""


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    category: str
    description: str
    correction: bool
    arguments: dict[str, str]


def _name(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not SAFE_NAME_RE.fullmatch(text):
        raise ToolValidationError(f"{field} inválido")
    return text


def _host(value: Any, field: str = "host") -> str:
    text = str(value or "").strip()
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        if not SAFE_HOST_RE.fullmatch(text) or text.startswith("-"):
            raise ToolValidationError(f"{field} inválido")
        return text


def _port(value: Any) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolValidationError("porta inválida") from exc
    if not 1 <= result <= 65535:
        raise ToolValidationError("porta fora do intervalo")
    return result


def _path(value: Any) -> str:
    text = str(value or "/").strip()
    if not SAFE_PATH_RE.fullmatch(text) or ".." in text.split("/"):
        raise ToolValidationError("caminho inválido")
    return text


def _lines(value: Any) -> int:
    try:
        result = int(value or 100)
    except (TypeError, ValueError) as exc:
        raise ToolValidationError("quantidade de linhas inválida") from exc
    return max(10, min(result, 500))


def _action(value: Any, *, omd: bool = False) -> str:
    allowed = {"start", "restart"} if omd else {"start", "restart", "reload", "enable --now"}
    text = str(value or "restart").strip().casefold()
    if text not in allowed:
        raise ToolValidationError(f"ação não permitida: {text}")
    return text


def describe_tools() -> list[dict[str, Any]]:
    descriptors = (
        ToolDescriptor("system.basics", "system", "Identidade, uptime, kernel e horário do host.", False, {}),
        ToolDescriptor("systemd.list_failed", "service", "Lista unidades systemd com falha.", False, {}),
        ToolDescriptor("systemd.inspect_unit", "service", "Inspeciona estado e configuração de uma unidade.", False, {"unit": "nome da unidade"}),
        ToolDescriptor("journal.read_unit", "logs", "Lê logs recentes de uma unidade systemd.", False, {"unit": "nome", "lines": "10-500"}),
        ToolDescriptor("network.interfaces", "network", "Lista interfaces, endereços e rotas.", False, {}),
        ToolDescriptor("network.inspect_route", "network", "Mostra a rota usada até um destino.", False, {"host": "IP/hostname"}),
        ToolDescriptor("network.test_port", "network", "Testa uma porta TCP sem alterar o destino.", False, {"host": "IP/hostname", "port": "1-65535"}),
        ToolDescriptor("network.udp_probe", "network", "Testa alcance UDP usando nc, quando disponível.", False, {"host": "IP/hostname", "port": "1-65535"}),
        ToolDescriptor("filesystem.usage", "filesystem", "Valida espaço e inodes de um filesystem.", False, {"path": "caminho absoluto"}),
        ToolDescriptor("filesystem.top_directories", "filesystem", "Lista maiores diretórios no primeiro nível.", False, {"path": "caminho absoluto"}),
        ToolDescriptor("memory.swap", "resources", "Coleta RAM, swap, vmstat e maiores processos.", False, {}),
        ToolDescriptor("docker.list_unhealthy", "container", "Lista containers unhealthy sem controlar ciclo de vida.", False, {}),
        ToolDescriptor("docker.inspect_health", "container", "Inspeciona o healthcheck de um container.", False, {"container": "nome"}),
        ToolDescriptor("checkmk.discover", "monitoring", "Descobre containers Checkmk e sites OMD.", False, {}),
        ToolDescriptor("checkmk.find_omd_service", "monitoring", "Localiza e consulta um serviço em todos os sites OMD.", False, {"service": "serviço OMD"}),
        ToolDescriptor("checkmk.find_host", "monitoring", "Procura um host nos sites Checkmk.", False, {"host": "hostname Checkmk"}),
        ToolDescriptor(
            "checkmk.diagnose_snmp_address",
            "monitoring",
            "Localiza no Checkmk o host que usa um IP SNMP e executa cmk -vvn dentro do site OMD correspondente.",
            False,
            {"address": "IP do equipamento SNMP"},
        ),
        ToolDescriptor("checkmk.inspect_agent_socket", "monitoring", "Valida socket, listener 6556 e resposta local do agente.", False, {}),
        ToolDescriptor("network.ssh_diagnostics", "network", "Valida sshd, listener e logs de negociação.", False, {}),
        ToolDescriptor("vpn.inspect", "network", "Valida interfaces, rotas e processos de VPN conhecidos.", False, {}),
        ToolDescriptor("systemd.recover_unit", "service", "Recupera somente unidades de monitoramento autorizadas.", True, {"unit": "unidade", "action": "start|restart|reload|enable --now"}),
        ToolDescriptor("checkmk.recover_omd_service", "monitoring", "Recupera serviço OMD autorizado dentro do container.", True, {"container": "nome", "site": "site", "service": "serviço", "action": "start|restart"}),
    )
    return [descriptor.__dict__ for descriptor in descriptors]


def resolve_tool(name: str, arguments: dict[str, Any] | None = None) -> ToolPlan:
    args = arguments or {}
    if name == "system.basics":
        return ToolPlan(name, "system", "hostname; uptime; uname -r; date --iso-8601=seconds", purpose="identificar host e estado básico")
    if name == "systemd.list_failed":
        return ToolPlan(name, "service", "systemctl --failed --no-pager --plain", purpose="listar unidades com falha")
    if name == "systemd.inspect_unit":
        unit = _name(args.get("unit"), "unit")
        command = f"systemctl show {shlex.quote(unit)} --no-pager -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState -p Result -p ExecMainStatus -p NRestarts"
        return ToolPlan(name, "service", command, purpose=f"inspecionar {unit}")
    if name == "journal.read_unit":
        unit = _name(args.get("unit"), "unit")
        lines = _lines(args.get("lines"))
        return ToolPlan(name, "logs", f"journalctl -u {shlex.quote(unit)} -n {lines} --no-pager", sudo=True, purpose=f"ler logs de {unit}")
    if name == "network.interfaces":
        return ToolPlan(name, "network", "ip -br address; ip route show", purpose="inspecionar interfaces e rotas")
    if name == "network.inspect_route":
        host = _host(args.get("host"))
        return ToolPlan(name, "network", f"ip route get {shlex.quote(host)}", purpose=f"inspecionar rota para {host}")
    if name == "network.test_port":
        host, port = _host(args.get("host")), _port(args.get("port"))
        command = f"timeout 6 bash -c {shlex.quote(f'</dev/tcp/{host}/{port}')}"
        return ToolPlan(name, "network", command, timeout=10, purpose=f"testar TCP {host}:{port}")
    if name == "network.udp_probe":
        host, port = _host(args.get("host")), _port(args.get("port"))
        return ToolPlan(name, "network", f"timeout 6 nc -zvu {shlex.quote(host)} {port}", timeout=10, purpose=f"testar UDP {host}:{port}")
    if name == "filesystem.usage":
        path = _path(args.get("path") or "/")
        return ToolPlan(name, "filesystem", f"df -hP {shlex.quote(path)}; df -iP {shlex.quote(path)}", purpose=f"validar espaço e inodes de {path}")
    if name == "filesystem.top_directories":
        path = _path(args.get("path") or "/")
        return ToolPlan(name, "filesystem", f"du -x -h --max-depth=1 {shlex.quote(path)} 2>/dev/null | sort -h | tail -n 20", sudo=True, timeout=180, purpose=f"localizar maiores diretórios em {path}")
    if name == "memory.swap":
        return ToolPlan(name, "resources", "free -h; vmstat 1 5; ps -eo pid,user,comm,%mem,rss --sort=-rss | head -n 16", purpose="analisar RAM e swap")
    if name == "docker.list_unhealthy":
        return ToolPlan(name, "container", "docker ps -a --filter health=unhealthy --format '{{.Names}}|{{.Image}}|{{.Status}}'", sudo=True, purpose="listar containers unhealthy")
    if name == "docker.inspect_health":
        container = _name(args.get("container"), "container")
        command = f"docker inspect --format {shlex.quote('{{json .State.Health}}')} {shlex.quote(container)}"
        return ToolPlan(name, "container", command, sudo=True, purpose=f"inspecionar healthcheck de {container}")
    if name == "checkmk.discover":
        command = "docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null | grep -Ei 'checkmk|check-mk' || true; for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'checkmk|check-mk'); do echo \"CONTAINER=$c\"; docker exec \"$c\" omd sites --bare 2>/dev/null || true; done"
        return ToolPlan(name, "monitoring", command, sudo=True, purpose="descobrir containers e sites Checkmk")
    if name == "checkmk.find_omd_service":
        service = _name(args.get("service"), "service")
        inner = f"omd status {service}"
        command = "for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'checkmk|check-mk'); do for s in $(docker exec \"$c\" omd sites --bare 2>/dev/null); do echo \"CONTAINER=$c SITE=$s SERVICE=" + service + "\"; docker exec \"$c\" su - \"$s\" -c " + shlex.quote(inner) + "; done; done"
        return ToolPlan(name, "monitoring", command, sudo=True, purpose=f"localizar serviço OMD {service}")
    if name == "checkmk.find_host":
        host = _host(args.get("host"))
        inner = f"cmk -D {shlex.quote(host)}"
        command = "for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'checkmk|check-mk'); do for s in $(docker exec \"$c\" omd sites --bare 2>/dev/null); do echo \"CONTAINER=$c SITE=$s HOST=" + host + "\"; docker exec \"$c\" su - \"$s\" -c " + shlex.quote(inner) + " 2>/dev/null && break; done; done"
        return ToolPlan(name, "monitoring", command, sudo=True, purpose=f"procurar host {host} no Checkmk")
    if name == "checkmk.diagnose_snmp_address":
        address = _host(args.get("address"), "address")
        inner = (
            f"target_ip={shlex.quote(address)}; found=0; "
            "for h in $(cmk -l 2>/dev/null); do "
            "data=$(cmk -D \"$h\" 2>/dev/null || true); "
            "if printf '%s\\n' \"$data\" | grep -Fq -- \"$target_ip\"; then "
            "found=1; echo \"MATCHED_HOST=$h ADDRESS=$target_ip\"; "
            "printf '%s\\n' \"$data\" | grep -E '^(Addresses:|Tags:|Host groups:|Contact groups:|Type of agent:|Agent mode:|SNMP)' || true; "
            "echo \"CHECK_BEGIN=$h\"; cmk -vvn \"$h\" 2>&1; rc=$?; echo \"CHECK_END=$h RC=$rc\"; "
            "fi; done; "
            "[ \"$found\" -eq 1 ] || echo \"NO_CHECKMK_HOST_FOR_ADDRESS=$target_ip\""
        )
        command = (
            "for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'checkmk|check-mk'); do "
            "for s in $(docker exec \"$c\" omd sites --bare 2>/dev/null); do "
            f"echo \"CONTAINER=$c SITE=$s ADDRESS={address}\"; "
            "docker exec \"$c\" su - \"$s\" -c " + shlex.quote(inner) + "; "
            "done; done"
        )
        return ToolPlan(
            name,
            "monitoring",
            command,
            sudo=True,
            timeout=300,
            purpose=f"localizar o host SNMP {address} nos sites Checkmk e executar cmk -vvn",
        )
    if name == "checkmk.inspect_agent_socket":
        command = "systemctl show check-mk-agent.socket check_mk.socket xinetd.socket xinetd.service --no-pager -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState 2>/dev/null; ss -lntp 2>/dev/null | grep -E '(:|\\])6556[[:space:]]' || true; timeout 12 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6556; head -n 12 <&3' 2>/dev/null || true"
        return ToolPlan(name, "monitoring", command, sudo=True, timeout=30, purpose="validar socket e resposta do agente Checkmk")
    if name == "network.ssh_diagnostics":
        command = "systemctl show sshd.service ssh.service --no-pager -p Id -p LoadState -p ActiveState -p SubState 2>/dev/null; ss -lntp 2>/dev/null | grep -E '(:|\\])22[[:space:]]' || true; journalctl -u sshd -u ssh -n 100 --no-pager 2>/dev/null | tail -n 100"
        return ToolPlan(name, "network", command, sudo=True, purpose="diagnosticar serviço e negociação SSH")
    if name == "vpn.inspect":
        command = "ip -br address; ip route show; ps -ef | grep -Ei '[o]penvpn|[w]ireguard|[c]loudflared|[s]trongswan|[c]haron'; systemctl --no-pager --plain --type=service --state=running | grep -Ei 'openvpn|wireguard|ipsec|strongswan' || true"
        return ToolPlan(name, "network", command, sudo=True, purpose="inspecionar interfaces, rotas e serviços VPN")
    if name == "systemd.recover_unit":
        unit = _name(args.get("unit"), "unit")
        action = _action(args.get("action"), omd=False)
        command = f"systemctl {action} {shlex.quote(unit)}"
        validation = f"systemctl is-active {shlex.quote(unit)}"
        extra: list[str] = []
        lowered = unit.casefold()
        if any(token in lowered for token in ("check-mk-agent", "check_mk", "xinetd")):
            extra.append("ss -lntp 2>/dev/null | grep -E '(:|\\])6556[[:space:]]'")
            extra.append("timeout 12 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6556; head -n 3 <&3' >/dev/null")
        if "snmp" in lowered:
            extra.append("ss -lunp 2>/dev/null | grep -E '(:|\\])161[[:space:]]'")
        return ToolPlan(name, "service", command, sudo=True, correction=True, preconditions=(f"systemctl show {shlex.quote(unit)} --no-pager -p LoadState -p ActiveState -p SubState -p UnitFileState",), validations=(validation, *extra), purpose=f"recuperar unidade {unit}")
    if name == "checkmk.recover_omd_service":
        container = _name(args.get("container"), "container")
        site = _name(args.get("site"), "site")
        service = _name(args.get("service"), "service")
        action = _action(args.get("action"), omd=True)
        command = f"docker exec {container} su - {site} -c 'omd {action} {service}'"
        validation = f"docker exec {container} su - {site} -c 'omd status {service}'"
        return ToolPlan(name, "monitoring", command, sudo=True, correction=True, preconditions=(validation,), validations=(validation,), purpose=f"recuperar {service} no site {site}")
    raise ToolValidationError(f"ferramenta desconhecida: {name}")


def _run_read(executor: SSHExecutor, environment: EnvironmentType, command: str, *, sudo: bool, timeout: int) -> dict[str, Any]:
    result = executor.run_sudo(command, environment, timeout=timeout) if sudo else executor.run(command, environment, timeout=timeout)
    return {
        "command": command,
        "exit_code": result.exit_code,
        "stdout": redact_text(result.stdout),
        "stderr": redact_text(result.stderr),
    }


def execute_tool(
    executor: SSHExecutor,
    environment: EnvironmentType,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    approved: bool = False,
) -> dict[str, Any]:
    try:
        plan = resolve_tool(name, arguments)
    except ToolValidationError as exc:
        return {"tool": name, "arguments": arguments or {}, "status": "blocked", "reason": str(exc), "exit_code": 255, "stdout": "", "stderr": "", "normalized": {}}

    base = {
        "tool": plan.name,
        "arguments": arguments or {},
        "command": plan.command,
        "purpose": plan.purpose,
        "category": plan.category,
        "sudo": plan.sudo,
        "preconditions": [],
        "validations": [],
        "rollback": None,
    }

    if plan.correction and not environment_allows_correction(environment):
        return {**base, "status": "blocked", "reason": f"ambiente {environment.value} não permite correção automática", "exit_code": 255, "stdout": "", "stderr": "", "normalized": {}}
    if plan.correction:
        decision = validate_correction(plan.command)
        if not decision.allowed:
            return {**base, "status": "blocked", "reason": decision.reason, "exit_code": 255, "stdout": "", "stderr": "", "normalized": {}}
        if not approved:
            return {**base, "status": "approval_required", "reason": "ação corretiva precisa de aprovação válida", "exit_code": 0, "stdout": "", "stderr": "", "normalized": {}}

    try:
        preconditions = [_run_read(executor, environment, command, sudo=plan.sudo, timeout=plan.timeout) for command in plan.preconditions]
        base["preconditions"] = preconditions
        if plan.correction:
            result = executor.run_sudo(plan.command, environment, approved=True, timeout=plan.timeout)
        else:
            result = executor.run_sudo(plan.command, environment, timeout=plan.timeout) if plan.sudo else executor.run(plan.command, environment, timeout=plan.timeout)

        stdout = redact_text(result.stdout)
        stderr = redact_text(result.stderr)
        validations: list[dict[str, Any]] = []
        if result.exit_code == 0:
            validations = [_run_read(executor, environment, command, sudo=plan.sudo, timeout=plan.timeout) for command in plan.validations]
        base["validations"] = validations
        validation_ok = all(item["exit_code"] == 0 for item in validations) if plan.validations else result.exit_code == 0
        status = "validated" if plan.correction and result.exit_code == 0 and validation_ok else "failed" if result.exit_code != 0 or (plan.correction and not validation_ok) else "executed"

        rollback: dict[str, Any] | None = None
        if plan.correction and status == "failed" and plan.rollback_command:
            rollback_result = executor.run_sudo(plan.rollback_command, environment, approved=True, timeout=plan.timeout)
            rollback = {"command": plan.rollback_command, "exit_code": rollback_result.exit_code, "stdout": redact_text(rollback_result.stdout), "stderr": redact_text(rollback_result.stderr)}
        base["rollback"] = rollback
        return {**base, "status": status, "exit_code": result.exit_code, "stdout": stdout, "stderr": stderr, "normalized": {}}
    except Exception as exc:
        return {**base, "status": "failed", "reason": f"{type(exc).__name__}: {exc}", "exit_code": 255, "stdout": "", "stderr": redact_text(str(exc)), "normalized": {}}
