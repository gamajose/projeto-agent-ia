from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict
from typing import Any

from google import genai

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.discovery import _clean, discover_host
from app.services.ssh import SSHExecutor

MAX_ROUNDS = 3
MAX_COMMANDS = 12

FORBIDDEN_TOKENS = (
    " rm ", "rm -", " reboot", "shutdown", "poweroff", "halt", "mkfs", "fdisk",
    "parted", "dd if=", "chmod ", "chown ", "userdel", "useradd", "passwd",
    "systemctl restart", "systemctl start", "systemctl stop", "service restart",
    "service start", "service stop", "docker restart", "docker start", "docker stop",
    "docker rm", "docker kill", "docker compose up", "docker compose down", ">", ">>",
    "curl |", "wget |", "bash -c", "sh -c", "eval ", "kill ", "pkill", "killall",
)

READ_ONLY_PATTERNS = [
    re.compile(r"^(uptime|hostname|hostnamectl|uname|nproc|free|vmstat|iostat|mpstat|sar|df|du|lsblk|blkid|mount|findmnt|lscpu|lsmem|ps|top|date|timedatectl|who|w|last|ip|ss|netstat|route|arp|ping|traceroute|tracepath|ethtool|resolvectl|getent|host|dig|nslookup|cat|head|tail|grep|awk|sed|cut|sort|uniq|wc|stat|find|ls|journalctl|dmesg)(\s|$)"),
    re.compile(r"^systemctl\s+(status|is-active|is-enabled|list-units|list-unit-files|show|cat)(\s|$)"),
    re.compile(r"^service\s+[A-Za-z0-9_.@:-]+\s+status$"),
    re.compile(r"^docker\s+(ps|info|version|inspect|logs|events|stats)(\s|$)"),
    re.compile(r"^docker\s+exec\s+[A-Za-z0-9_.-]+\s+(omd\s+(status|sites)|su\s+-\s+[A-Za-z0-9_-]+\s+-c\s+['\"]?(cmk\s+(-D|-d|-vvn|--list-hosts)|omd\s+(status|sites)|tail|grep|ps|cat|ls|df|free|uptime))"),
    re.compile(r"^cmk-agent-ctl\s+status(\s|$)"),
    re.compile(r"^snmp(get|walk|bulkwalk)(\s|$)"),
]

PLANNER_RULES = """
Você é o planejador de investigação de um agente AIOps Linux. Responda somente JSON válido.
Receba o objetivo do operador, a identidade do host e as evidências já coletadas.
Escolha dinamicamente os próximos comandos necessários para responder ao objetivo. Não use um roteiro fixo.

REGRAS:
- Gere somente comandos de investigação e leitura.
- Nunca gere reboot, shutdown, alteração de arquivo, instalação, remoção, start/stop/restart, kill ou acesso a banco de dados de cliente.
- Evite Checkmk, Docker e OMD quando o objetivo não estiver relacionado a monitoramento.
- Para CPU/memória/disco, priorize comandos como uptime, nproc, lscpu, free -h, vmstat 1 5, df -hT, df -i e lsblk.
- Para rede, use ip, ss, ping, traceroute/tracepath, getent/dig e logs pertinentes.
- Para serviço, primeiro descubra status e logs; não tente corrigir.
- Não repita comandos já executados.
- Limite a no máximo 6 comandos por rodada.
- sudo deve ser true apenas quando a leitura normalmente exige privilégio.

Formato:
{
  "objective": "resumo do objetivo",
  "reasoning_summary": "justificativa curta, sem cadeia de pensamento detalhada",
  "done": false,
  "commands": [
    {"command": "comando", "purpose": "o que valida", "sudo": false}
  ]
}
Se as evidências forem suficientes, use done=true e commands=[].
""".strip()

ANALYSIS_RULES = """
Você é um analista AIOps. Responda somente JSON válido usando exclusivamente as evidências executadas.
Não invente resultados. Relacione cada conclusão ao comando que a suporta.
Formato obrigatório:
{
  "summary": "resumo técnico",
  "facts": ["fatos comprovados"],
  "probable_cause": "causa provável ou inconclusiva",
  "conclusion": "conclusão objetiva",
  "recommendations": ["próximos passos seguros"],
  "ticket_report": "texto técnico para ticket"
}
""".strip()


def _json_from_text(text: str) -> dict[str, Any]:
    value = (text or "").strip()
    if value.startswith("```"):
        value = value.strip("`")
        if value.startswith("json"):
            value = value[4:].lstrip()
    return json.loads(value)


def _model_call(prompt: str) -> dict[str, Any] | None:
    settings = get_settings()
    if not settings.gemini_api_key:
        return None
    client = genai.Client(api_key=settings.gemini_api_key)
    models = [settings.gemini_model, "gemini-3.6-flash", "gemini-3.5-flash"]
    for model in dict.fromkeys(models):
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            return _json_from_text(response.text or "")
        except Exception:
            continue
    return None


def _fallback_plan(context: str, executed: set[str]) -> dict[str, Any]:
    text = context.casefold()
    commands: list[dict[str, Any]] = []

    def add(command: str, purpose: str, sudo: bool = False) -> None:
        if command not in executed:
            commands.append({"command": command, "purpose": purpose, "sudo": sudo})

    if any(word in text for word in ("memória", "memoria", "ram", "swap", "cpu", "processador", "lento", "lentidão", "lentidao")):
        add("uptime", "Validar carga e tempo de atividade")
        add("nproc; lscpu | head -n 30", "Identificar capacidade de CPU")
        add("free -h", "Validar RAM e swap")
        add("vmstat 1 5", "Validar CPU, memória e pressão de I/O")
    if any(word in text for word in ("disco", "filesystem", "file system", "espaço", "espaco", "inode", "partição", "particao")):
        add("df -hT", "Validar ocupação dos filesystems")
        add("df -i", "Validar consumo de inodes")
        add("lsblk -f", "Mapear discos, partições e filesystems")
    if any(word in text for word in ("rede", "comunicação", "comunicacao", "porta", "conexão", "conexao", "dns")):
        add("ip -br address; ip route", "Validar interfaces e rotas")
        add("ss -lntup", "Validar portas e sockets")
        add("cat /etc/resolv.conf", "Validar configuração DNS")
    if any(word in text for word in ("checkmk", "omd", "automation-helper", "monitoramento", "sensor")):
        add("docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' | grep -Ei 'checkmk|check-mk' || true", "Descobrir containers Checkmk", True)
    if not commands:
        add("uptime", "Validar carga geral")
        add("free -h", "Validar memória")
        add("df -hT", "Validar filesystems")
    return {"objective": context or "validar saúde do host", "reasoning_summary": "Plano de contingência por palavras-chave.", "done": False, "commands": commands[:6]}


def _safe_command(command: str) -> tuple[bool, str]:
    normalized = f" {command.strip().casefold()} "
    if not command.strip():
        return False, "comando vazio"
    if any(token in normalized for token in FORBIDDEN_TOKENS):
        return False, "comando contém operação proibida"
    if not any(pattern.search(command.strip()) for pattern in READ_ONLY_PATTERNS):
        return False, "comando fora da lista segura de investigação"
    return True, "autorizado"


def _execute(
    executor: SSHExecutor,
    environment: EnvironmentType,
    item: dict[str, Any],
) -> dict[str, Any]:
    command = str(item.get("command") or "").strip()
    safe, reason = _safe_command(command)
    if not safe:
        return {"command": command, "purpose": item.get("purpose", ""), "status": "blocked", "reason": reason, "exit_code": 255, "stdout": "", "stderr": ""}
    try:
        use_sudo = bool(item.get("sudo"))
        result = executor.run_sudo(command, environment, timeout=120) if use_sudo else executor.run(command, environment, timeout=120)
        if result.exit_code != 0 and not use_sudo:
            combined = f"{result.stdout}\n{result.stderr}".casefold()
            if any(token in combined for token in ("permission denied", "operation not permitted", "a senha é necessária", "a password is required")):
                result = executor.run_sudo(command, environment, timeout=120)
                use_sudo = True
        return {
            "command": command,
            "purpose": item.get("purpose", ""),
            "status": "executed",
            "sudo": use_sudo,
            "exit_code": result.exit_code,
            "stdout": _clean(result.stdout),
            "stderr": _clean(result.stderr),
        }
    except Exception as exc:
        return {"command": command, "purpose": item.get("purpose", ""), "status": "failed", "exit_code": 255, "stdout": "", "stderr": str(exc)}


def run_dynamic_investigation(
    *,
    executor: SSHExecutor,
    target: str,
    context: str,
    environment: EnvironmentType,
) -> dict[str, Any]:
    identity = asdict(discover_host(executor, environment))
    evidence: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []
    executed: set[str] = set()

    objective = context.strip() or "validar a saúde geral do servidor"
    for round_number in range(1, MAX_ROUNDS + 1):
        payload = {
            "target": target,
            "objective": objective,
            "identity": identity,
            "round": round_number,
            "already_executed": sorted(executed),
            "evidence": evidence,
        }
        plan = _model_call(PLANNER_RULES + "\n\nENTRADA:\n" + json.dumps(payload, ensure_ascii=False, default=str))
        if not plan:
            plan = _fallback_plan(objective, executed)
        plans.append(plan)
        if plan.get("done"):
            break

        commands = plan.get("commands") or []
        if not isinstance(commands, list) or not commands:
            break
        for item in commands[:6]:
            if len(executed) >= MAX_COMMANDS:
                break
            command = str(item.get("command") or "").strip()
            if not command or command in executed:
                continue
            executed.add(command)
            evidence.append(_execute(executor, environment, item))
        if len(executed) >= MAX_COMMANDS:
            break
        if not get_settings().gemini_api_key:
            break

    analysis_payload = {"target": target, "objective": objective, "identity": identity, "plans": plans, "evidence": evidence}
    analysis = _model_call(ANALYSIS_RULES + "\n\nDADOS:\n" + json.dumps(analysis_payload, ensure_ascii=False, default=str))
    if not analysis:
        successful = [item for item in evidence if item.get("status") == "executed"]
        analysis = {
            "summary": f"Foram executadas {len(successful)} verificações relacionadas ao objetivo informado.",
            "facts": [f"{item['command']} retornou código {item.get('exit_code')}." for item in successful],
            "probable_cause": "Análise automática inconclusiva sem resposta válida do modelo de IA.",
            "conclusion": "Consulte as evidências coletadas para concluir a validação.",
            "recommendations": [],
            "ticket_report": "Coleta técnica executada conforme o objetivo informado; resultados anexados para análise.",
        }

    return {"hostname": identity.get("hostname") or target, "target": target, "context": objective, "identity": identity, "plans": plans, "evidence": evidence, "analysis": analysis}
