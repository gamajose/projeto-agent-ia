from __future__ import annotations

import json
import re
import shlex
import time
from dataclasses import asdict
from typing import Any

from app.core.policies import EnvironmentType
from app.core.settings import get_settings
from app.services.ai_providers import get_provider
from app.services.command_catalog import validate_command
from app.services.discovery import _clean, discover_host
from app.services.persistence import recent_investigations, save_investigation
from app.services.ssh import SSHExecutor
from app.services.telemetry import deterministic_signals, normalize_evidence

MAX_OUTPUT_PER_COMMAND = 18000
MAX_DIAGNOSTIC_EXCERPT = 2000

PLANNER_RULES = """
Você é o planejador de um agente AIOps. Responda somente JSON válido.
Interprete o objetivo, o perfil do ambiente, o histórico e o estado atual da investigação.
Não siga roteiro fixo. Cada comando deve testar uma hipótese ou preencher uma lacuna real.
Gere somente comandos de leitura. Não repita comandos. Prefira ferramentas existentes no host.
O objetivo do operador tem prioridade absoluta. Não faça coleta genérica de CPU, memória ou disco
quando ela não for necessária para testar uma hipótese ligada ao problema informado.
Para objetivos relacionados a Checkmk, OMD, automation-helper, automation helpers, processos 2com,
monitoramento ou sensores, investigue primeiro a arquitetura real do Checkmk no host: containers,
sites OMD, status do site, processo/serviço citado e logs relacionados.
Formato:
{
  "objective":"...", "reasoning_summary":"...", "hypotheses":["..."],
  "confirmed_findings":["..."], "discarded_hypotheses":["..."],
  "missing_information":["..."], "done":false, "confidence":0,
  "commands":[{"command":"...", "purpose":"...", "sudo":false}]
}
Máximo de 5 comandos por rodada. confidence entre 0 e 100.
""".strip()

ROUND_RULES = """
Você é o analista AIOps de uma rodada. Responda somente JSON válido.
Interprete stdout, stderr, dados normalizados e sinais determinísticos. Código 0 não significa saúde.
Relacione toda afirmação a uma evidência executada. Identifique o que já foi confirmado, descartado e o que falta.
Formato:
{
  "round_summary":"...",
  "findings":[{"area":"cpu|memory|disk|io|network|service|monitoring|other","status":"healthy|attention|critical|inconclusive","statement":"...","evidence_command":"...","evidence_excerpt":"..."}],
  "hypotheses_confirmed":["..."], "hypotheses_discarded":["..."],
  "remaining_questions":["..."], "needs_more_evidence":true, "confidence":0
}
""".strip()

FINAL_RULES = """
Você é o analista AIOps responsável pela conclusão. Responda somente JSON válido.
Entregue a validação pronta. Use apenas as evidências executadas, os dados normalizados, sinais determinísticos e avaliações das rodadas.
Não peça ao operador para analisar manualmente. Quando inconclusivo, declare exatamente a lacuna.
Formato:
{
  "status":"healthy|attention|critical|inconclusive", "confidence":0,
  "summary":"...", "facts":["..."], "probable_cause":"...", "conclusion":"...",
  "recommendations":["..."],
  "evidence_map":[{"conclusion":"...","command":"...","evidence":"..."}],
  "ticket_report":"..."
}
""".strip()

CORRECTION_RULES = """
Você é o planejador de correção segura. Responda somente JSON válido.
Proponha apenas correções diretamente sustentadas pela conclusão, reversíveis e de baixo impacto.
Nunca proponha reboot, shutdown, remoção, alteração de arquivo, pacote, firewall, banco de cliente ou ciclo de vida de container.
São aceitos somente: systemctl start/restart/reload de uma unidade autorizada; service <unidade> start/restart/reload;
ou docker exec <container> su - <site> -c 'omd start|restart <serviço>'.
Toda ação precisa de validation_command somente leitura.
Formato: {"actions":[{"description":"...","command":"...","validation_command":"...","impact":"..."}]}
""".strip()

REPAIR_RULES = "Converta a resposta abaixo em JSON válido, sem inventar fatos. Retorne somente JSON."

SAFE_CORRECTIONS = (
    re.compile(r"^systemctl\s+(start|restart|reload)\s+[A-Za-z0-9_.@:-]+$"),
    re.compile(r"^service\s+[A-Za-z0-9_.@:-]+\s+(start|restart|reload)$"),
    re.compile(r"^docker\s+exec\s+[A-Za-z0-9_.-]+\s+su\s+-\s+[A-Za-z0-9_-]+\s+-c\s+'omd\s+(start|restart)\s+[A-Za-z0-9_.@:-]+'$"),
)


def _json_from_text(text: str) -> dict[str, Any]:
    value = (text or "").strip()
    value = re.sub(r"^```(?:json)?\s*", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\s*```$", "", value)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", value, flags=re.DOTALL)
        if not match:
            raise
        parsed = json.loads(match.group(0))
    return parsed if isinstance(parsed, dict) else {}


def _response_metadata(response: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    try:
        candidates = getattr(response, "candidates", None) or []
        metadata["candidate_count"] = len(candidates)
        if candidates:
            finish_reason = getattr(candidates[0], "finish_reason", None)
            metadata["finish_reason"] = str(finish_reason) if finish_reason is not None else None
    except Exception:
        pass
    try:
        feedback = getattr(response, "prompt_feedback", None)
        if feedback is not None:
            metadata["prompt_feedback"] = str(feedback)[:MAX_DIAGNOSTIC_EXCERPT]
    except Exception:
        pass
    return metadata


def _model_call(prompt: str, purpose: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    diagnostics: dict[str, Any] = {"purpose": purpose, "attempts": [], "success": False}
    try:
        provider = get_provider()
        attempt: dict[str, Any] = {"provider": provider.name, "model": provider.model}
        result, metadata = provider.generate_json(prompt)
        attempt.update(metadata)
        attempt["status"] = "success"
        diagnostics["attempts"].append(attempt)
        diagnostics.update({"success": True, "provider": provider.name, "model": provider.model})
        result["_ai_model"] = provider.model
        result["_ai_provider"] = provider.name
        return result, diagnostics
    except Exception as exc:
        diagnostics["error"] = f"{type(exc).__name__}: {exc}"
        return None, diagnostics

def _profile(identity: dict[str, Any], objective: str) -> str:
    text = f"{identity.get('os_name', '')} {objective}".casefold()
    if any(value in text for value in ("pfsense", "freebsd")):
        return "pfsense"
    if any(value in text for value in ("fortigate", "fortios")):
        return "fortigate"
    if any(value in text for value in ("esxi", "vmware")):
        return "vmware_esxi"
    if any(value in text for value in ("oracle database", "dataguard", "asm")):
        return "oracle_database"
    if any(value in text for value in (
        "checkmk", "check mk", "omd", "monitoramento", "sensor",
        "automation-helper", "automation helper", "automation helpers",
        "process 2com", "processo 2com",
    )):
        return "checkmk"
    if "oracle linux" in text:
        return "oracle_linux"
    return "linux_generic"


def _availability(executor: SSHExecutor, environment: EnvironmentType) -> dict[str, bool]:
    binaries = ("iostat", "mpstat", "sar", "dig", "traceroute", "tracepath", "docker", "cmk-agent-ctl", "snmpwalk")
    command = "; ".join(f"command -v {shlex.quote(binary)} >/dev/null 2>&1 && echo {binary}=1 || echo {binary}=0" for binary in binaries)
    result = executor.run(command, environment, timeout=30)
    return {line.split("=", 1)[0]: line.endswith("=1") for line in result.stdout.splitlines() if "=" in line}


def _execute(executor: SSHExecutor, environment: EnvironmentType, item: dict[str, Any], availability: dict[str, bool]) -> dict[str, Any]:
    command = str(item.get("command") or "").strip()
    safe, reason, spec = validate_command(command)
    if not safe:
        return {"command": command, "purpose": item.get("purpose", ""), "status": "blocked", "reason": reason, "exit_code": 255, "stdout": "", "stderr": "", "normalized": {}}
    if spec and spec.availability_binary and not availability.get(spec.availability_binary, True):
        return {"command": command, "purpose": item.get("purpose", ""), "status": "unavailable", "reason": f"{spec.availability_binary} não está instalado", "exit_code": 127, "stdout": "", "stderr": "", "normalized": {}}
    try:
        use_sudo = bool(item.get("sudo")) or bool(spec and spec.requires_sudo)
        timeout = spec.timeout if spec else 120
        result = executor.run_sudo(command, environment, timeout=timeout) if use_sudo else executor.run(command, environment, timeout=timeout)
        if result.exit_code != 0 and not use_sudo:
            combined = f"{result.stdout}\n{result.stderr}".casefold()
            if any(token in combined for token in ("permission denied", "operation not permitted", "a senha é necessária", "a password is required")):
                result = executor.run_sudo(command, environment, timeout=timeout)
                use_sudo = True
        stdout = _clean(result.stdout)[-MAX_OUTPUT_PER_COMMAND:]
        return {"command": command, "purpose": item.get("purpose", ""), "status": "executed", "sudo": use_sudo, "exit_code": result.exit_code, "stdout": stdout, "stderr": _clean(result.stderr)[-MAX_OUTPUT_PER_COMMAND:], "normalized": normalize_evidence(command, stdout), "category": spec.category if spec else "unknown"}
    except Exception as exc:
        return {"command": command, "purpose": item.get("purpose", ""), "status": "failed", "exit_code": 255, "stdout": "", "stderr": str(exc), "normalized": {}}


def _diagnostic_errors(diagnostics: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for diagnostic in diagnostics:
        purpose = diagnostic.get("purpose", "chamada_ia")
        if diagnostic.get("error"):
            errors.append(f"{purpose}: {diagnostic['error']}")
        for attempt in diagnostic.get("attempts") or []:
            if attempt.get("error") or attempt.get("parse_error"):
                errors.append(
                    f"{purpose}/{attempt.get('model')}: "
                    f"{attempt.get('error') or attempt.get('parse_error')}"
                )
    return list(dict.fromkeys(errors))


def _inconclusive(objective: str, diagnostics: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    errors = _diagnostic_errors(diagnostics)
    return {
        "status": "inconclusive",
        "confidence": 0,
        "summary": "A IA não conseguiu planejar ou concluir a investigação. Nenhuma coleta genérica foi usada como substituta.",
        "facts": [f"Objetivo recebido: {objective}.", f"Evidências executadas antes da falha: {len(evidence)}."],
        "probable_cause": " | ".join(errors) or "Falha não detalhada na API de IA.",
        "conclusion": "A operação foi interrompida porque não houve decisão válida da IA.",
        "recommendations": ["Corrigir a integração com a API Gemini usando o erro técnico exibido e executar novamente."],
        "evidence_map": [],
        "ticket_report": "A investigação automática não foi executada porque a API de IA não retornou um plano válido.",
    }


def _execute_corrections(executor: SSHExecutor, environment: EnvironmentType, analysis: dict[str, Any], approve: bool) -> list[dict[str, Any]]:
    proposal, _ = _model_call(CORRECTION_RULES + "\n\nANÁLISE:\n" + json.dumps(analysis, ensure_ascii=False), "correction_planning")
    actions: list[dict[str, Any]] = []
    for item in (proposal or {}).get("actions", []):
        command = str(item.get("command") or "").strip()
        validation_command = str(item.get("validation_command") or "").strip()
        if not any(pattern.fullmatch(command) for pattern in SAFE_CORRECTIONS):
            actions.append({**item, "status": "blocked", "reason": "fora da política de correção segura"})
            continue
        if not approve:
            actions.append({**item, "status": "approval_required"})
            continue
        try:
            execution = executor.run_sudo(command, environment, approved=True, timeout=120)
            valid, _, _ = validate_command(validation_command)
            validation = executor.run_sudo(validation_command, environment, timeout=120) if valid else None
            actions.append({**item, "status": "validated" if execution.exit_code == 0 and validation and validation.exit_code == 0 else "failed", "output": _clean(execution.stdout or execution.stderr), "validation": _clean(validation.stdout or validation.stderr) if validation else "validação bloqueada"})
        except Exception as exc:
            actions.append({**item, "status": "failed", "reason": str(exc)})
    return actions


def run_dynamic_investigation(*, executor: SSHExecutor, target: str, context: str, environment: EnvironmentType, mode: str = "investigate", approve: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    settings = get_settings()
    identity = asdict(discover_host(executor, environment))
    objective = context.strip() or "validar a saúde geral do servidor"
    profile = _profile(identity, objective)
    availability = _availability(executor, environment)
    history = recent_investigations(target=target, hostname=identity.get("hostname"), limit=5)
    evidence: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    executed: set[str] = set()
    state: dict[str, Any] = {"hypotheses": [], "confirmed_findings": [], "discarded_hypotheses": [], "remaining_questions": []}

    thresholds = {"filesystem_warning": settings.filesystem_warning_percent, "filesystem_critical": settings.filesystem_critical_percent, "load_warning_ratio": settings.load_warning_ratio, "load_critical_ratio": settings.load_critical_ratio}
    planner_failed = False

    for round_number in range(1, settings.agent_max_rounds + 1):
        payload = {"target": target, "objective": objective, "identity": identity, "profile": profile, "available_tools": availability, "history": history, "round": round_number, "investigation_state": state, "already_executed": sorted(executed), "evidence": evidence, "round_assessments": assessments, "thresholds": thresholds}
        plan, diag = _model_call(PLANNER_RULES + "\n\nENTRADA:\n" + json.dumps(payload, ensure_ascii=False, default=str), f"planning_round_{round_number}")
        diagnostics.append(diag)
        if not plan:
            planner_failed = True
            break
        plans.append(plan)
        if plan.get("done") and assessments:
            break
        commands = plan.get("commands") or []
        round_evidence: list[dict[str, Any]] = []
        for item in commands[:5]:
            if len(executed) >= settings.agent_max_commands:
                break
            command = str(item.get("command") or "").strip()
            if not command or command in executed:
                continue
            executed.add(command)
            result = _execute(executor, environment, item, availability)
            evidence.append(result)
            round_evidence.append(result)
        if not round_evidence:
            break
        normalized_items = [{"command": item["command"], "normalized": item.get("normalized") or {}} for item in evidence]
        signals = deterministic_signals(normalized_items, thresholds)
        assessment_payload = {"target": target, "objective": objective, "identity": identity, "profile": profile, "round": round_number, "plan": plan, "round_evidence": round_evidence, "deterministic_signals": signals, "previous_assessments": assessments, "thresholds": thresholds}
        assessment, diag = _model_call(ROUND_RULES + "\n\nDADOS:\n" + json.dumps(assessment_payload, ensure_ascii=False, default=str), f"analysis_round_{round_number}")
        diagnostics.append(diag)
        if not assessment:
            break
        assessments.append(assessment)
        state = {"hypotheses": plan.get("hypotheses") or [], "confirmed_findings": assessment.get("hypotheses_confirmed") or [], "discarded_hypotheses": assessment.get("hypotheses_discarded") or [], "remaining_questions": assessment.get("remaining_questions") or []}
        if not assessment.get("needs_more_evidence") and int(assessment.get("confidence") or 0) >= settings.agent_min_confidence:
            break
        if len(executed) >= settings.agent_max_commands:
            break

    signals = deterministic_signals([{"command": item["command"], "normalized": item.get("normalized") or {}} for item in evidence], thresholds)
    if planner_failed or not plans:
        analysis = _inconclusive(objective, diagnostics, evidence)
    else:
        final_payload = {"target": target, "objective": objective, "identity": identity, "profile": profile, "history": history, "plans": plans, "round_assessments": assessments, "evidence": evidence, "deterministic_signals": signals, "investigation_state": state, "thresholds": thresholds}
        analysis, diag = _model_call(FINAL_RULES + "\n\nDADOS:\n" + json.dumps(final_payload, ensure_ascii=False, default=str), "final_analysis")
        diagnostics.append(diag)
        if not analysis:
            analysis = _inconclusive(objective, diagnostics, evidence)
    analysis["ai_diagnostics"] = diagnostics

    ai_succeeded = bool(plans) and bool(assessments) and analysis.get("status") != "inconclusive"
    corrections = _execute_corrections(executor, environment, analysis, approve) if mode == "correct" and ai_succeeded else []
    duration_ms = int((time.monotonic() - started) * 1000)
    model = next((item.get("model") for item in reversed(diagnostics) if item.get("model")), None)
    investigation_id = save_investigation(target=target, hostname=identity.get("hostname"), objective=objective, environment=environment.value, mode=mode, status=str(analysis.get("status") or "inconclusive"), confidence=int(analysis.get("confidence") or 0), profile=profile, model=model, duration_ms=duration_ms, plans=plans, evidence=evidence, assessments=assessments, analysis=analysis, diagnostics=diagnostics)

    return {"investigation_id": investigation_id, "hostname": identity.get("hostname") or target, "target": target, "context": objective, "identity": identity, "profile": profile, "available_tools": availability, "history": history, "plans": plans, "round_assessments": assessments, "evidence": evidence, "deterministic_signals": signals, "analysis": analysis, "corrections": corrections, "duration_ms": duration_ms, "ai_diagnostics": diagnostics}
