from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Any

from google import genai

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.discovery import _clean, discover_host
from app.services.ssh import SSHExecutor

MAX_ROUNDS = 5
MAX_COMMANDS = 20
MAX_OUTPUT_PER_COMMAND = 18000

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
Você é o investigador principal de um agente AIOps Linux. Responda somente JSON válido.
Seu trabalho não é seguir playbook fixo: interprete o objetivo, mantenha hipóteses e decida a próxima coleta com base nas evidências reais já obtidas.

REGRAS:
- Gere somente comandos de investigação e leitura.
- Nunca gere reboot, shutdown, alteração de arquivo, instalação, remoção, start/stop/restart, kill ou acesso a banco de dados de cliente.
- Evite Checkmk, Docker e OMD quando o objetivo não estiver relacionado a monitoramento.
- Não repita comandos já executados.
- Limite a no máximo 5 comandos por rodada.
- Cada comando deve testar uma hipótese ou preencher uma lacuna concreta.
- sudo deve ser true apenas quando a leitura normalmente exige privilégio.
- Analise as saídas, não apenas os códigos de retorno.
- Só use done=true quando houver evidência suficiente para responder ao objetivo com segurança.
- Quando houver ambiguidade, solicite uma nova coleta em vez de concluir prematuramente.

Formato obrigatório:
{
  "objective": "resumo do objetivo",
  "reasoning_summary": "justificativa técnica curta e compartilhável",
  "hypotheses": ["hipóteses ainda consideradas"],
  "confirmed_findings": ["achados já comprovados"],
  "discarded_hypotheses": ["hipóteses descartadas pelas evidências"],
  "missing_information": ["o que ainda falta saber"],
  "done": false,
  "confidence": 0,
  "commands": [
    {"command": "comando", "purpose": "hipótese ou métrica validada", "sudo": false}
  ]
}
confidence deve ser inteiro de 0 a 100.
""".strip()

ROUND_ANALYSIS_RULES = """
Você é um analista AIOps avaliando uma rodada de investigação. Responda somente JSON válido.
Interprete os valores presentes em stdout/stderr; código 0 só prova que o comando executou, não que o recurso está saudável.
Relacione cada afirmação ao comando correspondente. Não invente limites, valores ou resultados.

Formato obrigatório:
{
  "round_summary": "o que esta rodada demonstrou",
  "findings": [
    {"area": "cpu|memory|disk|io|network|service|monitoring|other", "status": "healthy|attention|critical|inconclusive", "statement": "interpretação objetiva", "evidence_command": "comando", "evidence_excerpt": "trecho curto da saída"}
  ],
  "hypotheses_confirmed": ["hipóteses confirmadas"],
  "hypotheses_discarded": ["hipóteses descartadas"],
  "remaining_questions": ["lacunas reais"],
  "needs_more_evidence": true,
  "confidence": 0
}
confidence deve ser inteiro de 0 a 100.
""".strip()

FINAL_ANALYSIS_RULES = """
Você é o analista AIOps responsável pela conclusão final. Responda somente JSON válido.
Use exclusivamente as evidências executadas e as avaliações das rodadas.
Interprete tecnicamente CPU, load, memória disponível, swap, vmstat, disco, inode, I/O, rede, serviços ou monitoramento conforme o objetivo.
Código de retorno 0 não significa saúde. Não declare normalidade sem valores que sustentem isso.
Não diga para o operador analisar manualmente. Entregue a validação pronta, ou declare exatamente qual lacuna impediu a conclusão.

Formato obrigatório:
{
  "status": "healthy|attention|critical|inconclusive",
  "confidence": 0,
  "summary": "resumo técnico direto",
  "facts": ["fatos comprovados com valores"],
  "probable_cause": "causa provável, ausência de anomalia ou motivo exato da inconclusão",
  "conclusion": "resposta objetiva ao pedido do operador",
  "recommendations": ["próximos passos seguros e específicos"],
  "evidence_map": [
    {"conclusion": "conclusão", "command": "comando", "evidence": "valor ou trecho que sustenta"}
  ],
  "ticket_report": "texto técnico pronto para ticket"
}
confidence deve ser inteiro de 0 a 100.
""".strip()

REPAIR_RULES = """
Converta a resposta abaixo em JSON válido, sem adicionar fatos e mantendo os campos solicitados no prompt original. Retorne somente JSON.
""".strip()


def _json_from_text(text: str) -> dict[str, Any]:
    value = (text or "").strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*", "", value, flags=re.IGNORECASE)
        value = re.sub(r"\s*```$", "", value)
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", value, flags=re.DOTALL)
        if not match:
            raise
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else {}


def _model_call(prompt: str, purpose: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    settings = get_settings()
    diagnostics: dict[str, Any] = {"purpose": purpose, "attempts": [], "success": False}
    if not settings.gemini_api_key:
        diagnostics["error"] = "GEMINI_API_KEY não configurada."
        return None, diagnostics

    client = genai.Client(api_key=settings.gemini_api_key)
    models = [settings.gemini_model, "gemini-2.5-flash", "gemini-2.0-flash"]
    for model in dict.fromkeys(filter(None, models)):
        attempt: dict[str, Any] = {"model": model}
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            raw_text = response.text or ""
            attempt["response_chars"] = len(raw_text)
            try:
                result = _json_from_text(raw_text)
            except Exception as parse_exc:
                attempt["parse_error"] = f"{type(parse_exc).__name__}: {parse_exc}"
                try:
                    repair = client.models.generate_content(
                        model=model,
                        contents=REPAIR_RULES + "\n\nRESPOSTA:\n" + raw_text,
                    )
                    result = _json_from_text(repair.text or "")
                    attempt["repaired"] = True
                except Exception as repair_exc:
                    attempt["repair_error"] = f"{type(repair_exc).__name__}: {repair_exc}"
                    diagnostics["attempts"].append(attempt)
                    continue
            if result:
                attempt["status"] = "success"
                diagnostics["attempts"].append(attempt)
                diagnostics.update({"success": True, "model": model})
                result["_ai_model"] = model
                return result, diagnostics
            attempt["error"] = "Resposta JSON vazia."
        except Exception as exc:
            attempt["error"] = f"{type(exc).__name__}: {exc}"
        diagnostics["attempts"].append(attempt)

    diagnostics["error"] = "Nenhum modelo retornou uma resposta JSON válida."
    return None, diagnostics


def _fallback_plan(context: str, executed: set[str]) -> dict[str, Any]:
    text = context.casefold()
    commands: list[dict[str, Any]] = []

    def add(command: str, purpose: str, sudo: bool = False) -> None:
        if command not in executed:
            commands.append({"command": command, "purpose": purpose, "sudo": sudo})

    if any(word in text for word in ("memória", "memoria", "ram", "swap", "cpu", "processador", "lento", "lentidão", "lentidao")):
        add("uptime", "Comparar load average com a capacidade de CPU")
        add("nproc; lscpu | head -n 30", "Identificar quantidade e arquitetura das CPUs")
        add("free -h", "Medir RAM disponível, cache e swap")
        add("vmstat 1 5", "Medir fila de CPU, swap, I/O e espera")
    if any(word in text for word in ("disco", "filesystem", "file system", "espaço", "espaco", "inode", "partição", "particao")):
        add("df -hT", "Medir ocupação e espaço livre dos filesystems")
        add("df -i", "Medir utilização de inodes")
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
    return {
        "objective": context or "validar saúde do host",
        "reasoning_summary": "Plano mínimo de contingência porque a IA não respondeu.",
        "hypotheses": [],
        "confirmed_findings": [],
        "discarded_hypotheses": [],
        "missing_information": [],
        "done": False,
        "confidence": 0,
        "commands": commands[:5],
        "_fallback": True,
    }


def _safe_command(command: str) -> tuple[bool, str]:
    normalized = f" {command.strip().casefold()} "
    if not command.strip():
        return False, "comando vazio"
    if any(token in normalized for token in FORBIDDEN_TOKENS):
        return False, "comando contém operação proibida"
    first_command = command.strip().split(";", 1)[0].strip()
    if not any(pattern.search(first_command) for pattern in READ_ONLY_PATTERNS):
        return False, "comando fora da lista segura de investigação"
    return True, "autorizado"


def _execute(executor: SSHExecutor, environment: EnvironmentType, item: dict[str, Any]) -> dict[str, Any]:
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
            "stdout": _clean(result.stdout)[-MAX_OUTPUT_PER_COMMAND:],
            "stderr": _clean(result.stderr)[-MAX_OUTPUT_PER_COMMAND:],
        }
    except Exception as exc:
        return {"command": command, "purpose": item.get("purpose", ""), "status": "failed", "exit_code": 255, "stdout": "", "stderr": str(exc)}


def _inconclusive_analysis(objective: str, diagnostics: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    errors = [item.get("error") for item in diagnostics if item.get("error")]
    return {
        "status": "inconclusive",
        "confidence": 0,
        "summary": "A coleta foi executada, porém a validação por IA não foi concluída.",
        "facts": [f"Foram coletadas {len(evidence)} evidências para o objetivo: {objective}."],
        "probable_cause": "; ".join(errors) or "O modelo não retornou análise estruturada válida.",
        "conclusion": "Nenhuma conclusão técnica automática foi emitida sem uma análise válida da IA.",
        "recommendations": ["Validar a chave, o modelo e a conectividade com a API de IA e executar novamente."],
        "evidence_map": [],
        "ticket_report": "A coleta técnica foi realizada, mas a etapa de validação por IA ficou inconclusiva por indisponibilidade ou resposta inválida do modelo. Nenhuma conclusão operacional foi emitida.",
        "ai_diagnostics": diagnostics,
    }


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
    round_assessments: list[dict[str, Any]] = []
    ai_diagnostics: list[dict[str, Any]] = []
    executed: set[str] = set()
    investigation_state: dict[str, Any] = {
        "hypotheses": [],
        "confirmed_findings": [],
        "discarded_hypotheses": [],
        "remaining_questions": [],
    }

    objective = context.strip() or "validar a saúde geral do servidor"
    for round_number in range(1, MAX_ROUNDS + 1):
        payload = {
            "target": target,
            "objective": objective,
            "identity": identity,
            "round": round_number,
            "investigation_state": investigation_state,
            "already_executed": sorted(executed),
            "evidence": evidence,
            "round_assessments": round_assessments,
        }
        plan, plan_diag = _model_call(
            PLANNER_RULES + "\n\nENTRADA:\n" + json.dumps(payload, ensure_ascii=False, default=str),
            f"planning_round_{round_number}",
        )
        ai_diagnostics.append(plan_diag)
        if not plan:
            plan = _fallback_plan(objective, executed)
        plans.append(plan)

        if plan.get("done") and round_assessments:
            break
        commands = plan.get("commands") or []
        if not isinstance(commands, list) or not commands:
            break

        round_evidence: list[dict[str, Any]] = []
        for item in commands[:5]:
            if len(executed) >= MAX_COMMANDS:
                break
            command = str(item.get("command") or "").strip()
            if not command or command in executed:
                continue
            executed.add(command)
            result = _execute(executor, environment, item)
            evidence.append(result)
            round_evidence.append(result)

        if not round_evidence:
            break

        assessment_payload = {
            "target": target,
            "objective": objective,
            "identity": identity,
            "round": round_number,
            "plan": plan,
            "round_evidence": round_evidence,
            "previous_assessments": round_assessments,
        }
        assessment, assessment_diag = _model_call(
            ROUND_ANALYSIS_RULES + "\n\nDADOS:\n" + json.dumps(assessment_payload, ensure_ascii=False, default=str),
            f"analysis_round_{round_number}",
        )
        ai_diagnostics.append(assessment_diag)
        if assessment:
            round_assessments.append(assessment)
            investigation_state = {
                "hypotheses": plan.get("hypotheses") or [],
                "confirmed_findings": assessment.get("hypotheses_confirmed") or [],
                "discarded_hypotheses": assessment.get("hypotheses_discarded") or [],
                "remaining_questions": assessment.get("remaining_questions") or [],
            }
            if not assessment.get("needs_more_evidence") and int(assessment.get("confidence") or 0) >= 70:
                break
        elif not get_settings().gemini_api_key:
            break

        if len(executed) >= MAX_COMMANDS:
            break

    final_payload = {
        "target": target,
        "objective": objective,
        "identity": identity,
        "plans": plans,
        "round_assessments": round_assessments,
        "evidence": evidence,
        "investigation_state": investigation_state,
    }
    analysis, final_diag = _model_call(
        FINAL_ANALYSIS_RULES + "\n\nDADOS:\n" + json.dumps(final_payload, ensure_ascii=False, default=str),
        "final_analysis",
    )
    ai_diagnostics.append(final_diag)
    if not analysis:
        analysis = _inconclusive_analysis(objective, ai_diagnostics, evidence)
    else:
        analysis["ai_diagnostics"] = ai_diagnostics

    return {
        "hostname": identity.get("hostname") or target,
        "target": target,
        "context": objective,
        "identity": identity,
        "plans": plans,
        "round_assessments": round_assessments,
        "evidence": evidence,
        "analysis": analysis,
        "ai_diagnostics": ai_diagnostics,
    }
