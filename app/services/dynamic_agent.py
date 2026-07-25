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
from app.services.approvals import create_approval_token
from app.services.command_catalog import validate_command
from app.services.discovery import _clean, discover_host
from app.services.environment_classifier import classify_environment
from app.services.helpdesk import publish_ticket_report
from app.services.persistence import (
    recent_investigations,
    save_investigation,
    similar_investigations,
    update_investigation_analysis,
)
from app.services.playbooks import playbook_summary, render_steps, select_playbook
from app.services.redaction import redact_object, redact_text
from app.services.reviewer import review_corrections
from app.services.ssh import SSHExecutor
from app.services.telemetry import deterministic_signals, normalize_evidence
from app.services.tool_registry import describe_tools, execute_tool, resolve_tool


MAX_OUTPUT_PER_COMMAND = 18000
MAX_DIAGNOSTIC_EXCERPT = 2000

PLANNER_RULES = """
Você é o planejador de um agente AIOps orientado a ferramentas. Responda somente JSON válido.
Interprete objetivo, playbook selecionado, histórico similar e evidências já coletadas.
Escolha exclusivamente ferramentas do catálogo fornecido; não escreva shell quando existir ferramenta.
Cada ferramenta deve testar uma hipótese ou preencher uma lacuna real. Não repita coletas.
As ferramentas desta fase são somente leitura. O objetivo do operador tem prioridade absoluta.
Formato:
{
  "objective":"...", "reasoning_summary":"...", "hypotheses":["..."],
  "confirmed_findings":["..."], "discarded_hypotheses":["..."],
  "missing_information":["..."], "done":false, "confidence":0,
  "tools":[{"tool":"systemd.inspect_unit","arguments":{"unit":"..."},"purpose":"..."}]
}
Máximo de 5 ferramentas por rodada. confidence entre 0 e 100.
""".strip()

ROUND_RULES = """
Você é o analista AIOps de uma rodada. Responda somente JSON válido.
Interprete stdout, stderr, pré-condições, pós-validações, dados normalizados e sinais determinísticos.
Código de retorno zero não significa saúde. Toda afirmação precisa apontar para evidência executada.
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
Use apenas evidências executadas, dados normalizados, sinais determinísticos e avaliações das rodadas.
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
Você é o planejador de correção segura de um agente AIOps. Responda somente JSON válido.
Use apenas as ferramentas corretivas explicitamente permitidas pelo playbook.
Não escreva comandos shell. Não proponha reboot, shutdown, banco de cliente, firewall,
pacotes, arquivos, remoção, parada isolada ou ciclo de vida de container.
Cada ação precisa estar diretamente sustentada pela causa provável.
Formato:
{
  "actions":[{
    "description":"...", "tool":"systemd.recover_unit",
    "arguments":{"unit":"check-mk-agent.socket","action":"start"},
    "impact":"baixo", "evidence_reason":"..."
  }]
}
""".strip()


def _model_call(prompt: str, purpose: str, provider_name: str | None = None) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    diagnostics: dict[str, Any] = {"purpose": purpose, "attempts": [], "success": False}
    try:
        provider = get_provider(provider_name)
        attempt: dict[str, Any] = {"provider": provider.name, "model": provider.model}
        result, metadata = provider.generate_json(redact_text(prompt))
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
    binaries = ("iostat", "mpstat", "sar", "dig", "traceroute", "tracepath", "docker", "cmk-agent-ctl", "snmpwalk", "nc")
    command = "; ".join(f"command -v {shlex.quote(binary)} >/dev/null 2>&1 && echo {binary}=1 || echo {binary}=0" for binary in binaries)
    result = executor.run(command, environment, timeout=30)
    return {line.split("=", 1)[0]: line.endswith("=1") for line in result.stdout.splitlines() if "=" in line}


def _execute_legacy(executor: SSHExecutor, environment: EnvironmentType, item: dict[str, Any], availability: dict[str, bool]) -> dict[str, Any]:
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
        stdout = redact_text(_clean(result.stdout)[-MAX_OUTPUT_PER_COMMAND:])
        return {"command": command, "purpose": item.get("purpose", ""), "status": "executed", "sudo": use_sudo, "exit_code": result.exit_code, "stdout": stdout, "stderr": redact_text(_clean(result.stderr)[-MAX_OUTPUT_PER_COMMAND:]), "normalized": normalize_evidence(command, stdout), "category": spec.category if spec else "unknown", "legacy_command": True}
    except Exception as exc:
        return {"command": command, "purpose": item.get("purpose", ""), "status": "failed", "exit_code": 255, "stdout": "", "stderr": redact_text(str(exc)), "normalized": {}, "legacy_command": True}


def _execute_item(executor: SSHExecutor, environment: EnvironmentType, item: dict[str, Any], availability: dict[str, bool]) -> dict[str, Any]:
    tool_name = str(item.get("tool") or "").strip()
    if tool_name:
        result = execute_tool(executor, environment, tool_name, dict(item.get("arguments") or {}), approved=False)
        result["purpose"] = item.get("purpose") or result.get("purpose")
        stdout = str(result.get("stdout") or "")[-MAX_OUTPUT_PER_COMMAND:]
        result["stdout"] = stdout
        result["normalized"] = normalize_evidence(str(result.get("command") or tool_name), stdout)
        return redact_object(result)
    if get_settings().agent_allow_legacy_read_commands:
        return _execute_legacy(executor, environment, item, availability)
    return {"status": "blocked", "reason": "o planejador precisa selecionar uma ferramenta estruturada", "command": str(item.get("command") or ""), "exit_code": 255, "stdout": "", "stderr": "", "normalized": {}}


def _diagnostic_errors(diagnostics: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for diagnostic in diagnostics:
        purpose = diagnostic.get("purpose", "chamada_ia")
        if diagnostic.get("error"):
            errors.append(f"{purpose}: {diagnostic['error']}")
        for attempt in diagnostic.get("attempts") or []:
            if attempt.get("error") or attempt.get("parse_error"):
                errors.append(f"{purpose}/{attempt.get('model')}: {attempt.get('error') or attempt.get('parse_error')}")
    return list(dict.fromkeys(errors))


def _inconclusive(objective: str, diagnostics: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    errors = _diagnostic_errors(diagnostics)
    return {
        "status": "inconclusive",
        "confidence": 0,
        "summary": "A IA não conseguiu planejar ou concluir a investigação. Nenhuma coleta genérica foi usada como substituta.",
        "facts": [f"Objetivo recebido: {objective}.", f"Evidências executadas antes da falha: {len(evidence)}."],
        "probable_cause": " | ".join(errors) or "Falha não detalhada no provedor de IA.",
        "conclusion": "A operação foi interrompida porque não houve decisão válida da IA.",
        "recommendations": ["Corrigir a integração com o provedor de IA exibido no diagnóstico e executar novamente."],
        "evidence_map": [],
        "ticket_report": "A investigação automática não foi concluída porque o provedor de IA não retornou um plano válido.",
    }


def _prepare_corrections(analysis: dict[str, Any], evidence: list[dict[str, Any]], playbook: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    allowed = list((playbook or {}).get("allowed_corrections") or [])
    if str(analysis.get("status") or "") not in {"attention", "critical"} or not allowed:
        return [], {"purpose": "correction_planning", "success": True, "status": "not_required"}
    prompt = CORRECTION_RULES + "\n\nFERRAMENTAS PERMITIDAS:\n" + json.dumps(allowed, ensure_ascii=False) + "\n\nANÁLISE E EVIDÊNCIAS:\n" + json.dumps(redact_object({"analysis": analysis, "evidence": evidence[-12:]}), ensure_ascii=False, default=str)
    proposal, diagnostics = _model_call(prompt, "correction_planning")
    actions: list[dict[str, Any]] = []
    for item in (proposal or {}).get("actions") or []:
        tool = str(item.get("tool") or "")
        arguments = dict(item.get("arguments") or {})
        if tool not in allowed:
            actions.append({**item, "status": "blocked", "reason": "ferramenta não permitida pelo playbook"})
            continue
        try:
            plan = resolve_tool(tool, arguments)
        except Exception as exc:
            actions.append({**item, "status": "blocked", "reason": str(exc)})
            continue
        if not plan.correction:
            actions.append({**item, "status": "blocked", "reason": "ferramenta não é corretiva"})
            continue
        actions.append({
            **item,
            "tool": tool,
            "arguments": arguments,
            "command": plan.command,
            "preconditions": list(plan.preconditions),
            "validations": list(plan.validations),
            "rollback_available": bool(plan.rollback_command),
            "status": "proposed",
        })
    return redact_object(actions), diagnostics


def _apply_corrections(
    executor: SSHExecutor,
    environment: EnvironmentType,
    proposals: list[dict[str, Any]],
    *,
    approved: bool,
    reviewer: dict[str, Any],
) -> list[dict[str, Any]]:
    if not proposals:
        return []
    if not approved:
        return [{**item, "status": "approval_required"} for item in proposals]
    if not reviewer.get("approved"):
        return [{**item, "status": "review_rejected", "review_reason": reviewer.get("reason")} for item in proposals]
    return [
        {
            **item,
            **execute_tool(executor, environment, str(item.get("tool")), dict(item.get("arguments") or {}), approved=True),
        }
        for item in proposals
        if item.get("status") != "blocked"
    ]


def run_dynamic_investigation(
    *,
    executor: SSHExecutor,
    target: str,
    context: str,
    environment: EnvironmentType,
    mode: str = "propose",
    approve: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    settings = get_settings()
    identity = asdict(discover_host(executor, environment))
    objective = context.strip() or "validar a saúde geral do servidor"
    profile = _profile(identity, objective)
    classification = classify_environment(requested=environment, hostname=identity.get("hostname"), objective=objective)
    effective_environment = classification.environment
    availability = _availability(executor, effective_environment)
    history = recent_investigations(target=target, hostname=identity.get("hostname"), limit=5)
    similar_history = similar_investigations(objective=objective, profile=profile, target=target, limit=5)
    playbook_obj = select_playbook(objective, profile)
    playbook = playbook_summary(playbook_obj)

    evidence: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    executed: set[str] = set()
    state: dict[str, Any] = {"hypotheses": [], "confirmed_findings": [], "discarded_hypotheses": [], "remaining_questions": []}
    thresholds = {"filesystem_warning": settings.filesystem_warning_percent, "filesystem_critical": settings.filesystem_critical_percent, "load_warning_ratio": settings.load_warning_ratio, "load_critical_ratio": settings.load_critical_ratio}

    playbook_context = {"target": target, "hostname": identity.get("hostname") or target}
    initial_steps = render_steps(playbook_obj, playbook_context)
    if initial_steps:
        plans.append({"source": "playbook", "playbook": playbook, "reasoning_summary": f"Coleta inicial definida pelo playbook {playbook_obj.title}.", "tools": initial_steps, "hypotheses": []})
        for item in initial_steps[: settings.agent_max_commands]:
            key = json.dumps({"tool": item.get("tool"), "arguments": item.get("arguments") or {}}, sort_keys=True)
            if key in executed:
                continue
            executed.add(key)
            evidence.append(_execute_item(executor, effective_environment, item, availability))

    planner_failed = False
    for round_number in range(1, settings.agent_max_rounds + 1):
        payload = redact_object({
            "target": target,
            "objective": objective,
            "identity": identity,
            "profile": profile,
            "environment": classification.__dict__,
            "available_binaries": availability,
            "tool_catalog": [item for item in describe_tools() if not item["correction"]],
            "playbook": playbook,
            "history": history,
            "similar_history": similar_history,
            "round": round_number,
            "investigation_state": state,
            "already_executed": sorted(executed),
            "evidence": evidence,
            "round_assessments": assessments,
            "thresholds": thresholds,
        })
        plan, diag = _model_call(PLANNER_RULES + "\n\nENTRADA:\n" + json.dumps(payload, ensure_ascii=False, default=str), f"planning_round_{round_number}")
        diagnostics.append(diag)
        if not plan:
            planner_failed = not bool(evidence)
            break
        plans.append(plan)
        if plan.get("done") and assessments:
            break
        items = plan.get("tools") or plan.get("commands") or []
        round_evidence: list[dict[str, Any]] = []
        for item in items[:5]:
            if len(executed) >= settings.agent_max_commands:
                break
            key = json.dumps({"tool": item.get("tool"), "arguments": item.get("arguments") or {}, "command": item.get("command")}, sort_keys=True)
            if key in executed:
                continue
            executed.add(key)
            result = _execute_item(executor, effective_environment, item, availability)
            evidence.append(result)
            round_evidence.append(result)
        if not round_evidence:
            break
        normalized_items = [{"command": item.get("command") or item.get("tool"), "normalized": item.get("normalized") or {}} for item in evidence]
        signals = deterministic_signals(normalized_items, thresholds)
        assessment_payload = redact_object({"target": target, "objective": objective, "identity": identity, "profile": profile, "round": round_number, "plan": plan, "round_evidence": round_evidence, "deterministic_signals": signals, "previous_assessments": assessments, "thresholds": thresholds})
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

    signals = deterministic_signals([{"command": item.get("command") or item.get("tool"), "normalized": item.get("normalized") or {}} for item in evidence], thresholds)
    if planner_failed or not plans:
        analysis = _inconclusive(objective, diagnostics, evidence)
    else:
        final_payload = redact_object({"target": target, "objective": objective, "identity": identity, "profile": profile, "environment": classification.__dict__, "history": history, "similar_history": similar_history, "playbook": playbook, "plans": plans, "round_assessments": assessments, "evidence": evidence, "deterministic_signals": signals, "investigation_state": state, "thresholds": thresholds})
        analysis, diag = _model_call(FINAL_RULES + "\n\nDADOS:\n" + json.dumps(final_payload, ensure_ascii=False, default=str), "final_analysis")
        diagnostics.append(diag)
        if not analysis:
            analysis = _inconclusive(objective, diagnostics, evidence)

    proposals, correction_diag = _prepare_corrections(analysis, evidence, playbook)
    diagnostics.append(correction_diag)
    reviewer = review_corrections(analysis, [item for item in proposals if item.get("status") == "proposed"], evidence, settings=settings)
    analysis["proposed_actions"] = proposals
    analysis["review"] = reviewer
    analysis["ai_diagnostics"] = diagnostics

    may_execute = mode == "correct" and approve and classification.trusted_for_changes
    if settings.ai_reviewer_required_for_corrections and not reviewer.get("approved"):
        may_execute = False
    corrections = _apply_corrections(executor, effective_environment, proposals, approved=may_execute, reviewer=reviewer)

    duration_ms = int((time.monotonic() - started) * 1000)
    model = next((item.get("model") for item in reversed(diagnostics) if item.get("model")), None)
    investigation_id = save_investigation(
        target=target,
        hostname=identity.get("hostname"),
        objective=objective,
        environment=effective_environment.value,
        mode=mode,
        status=str(analysis.get("status") or "inconclusive"),
        confidence=int(analysis.get("confidence") or 0),
        profile=profile,
        model=model,
        duration_ms=duration_ms,
        plans=redact_object(plans),
        evidence=redact_object(evidence),
        assessments=redact_object(assessments),
        analysis=redact_object(analysis),
        diagnostics=redact_object(diagnostics),
    )

    approval_token = None
    if mode == "propose" and reviewer.get("approved") and classification.trusted_for_changes:
        approved_actions = [item for item in proposals if item.get("status") == "proposed"]
        approval_token = create_approval_token(investigation_id, target, approved_actions, settings=settings)
        if approval_token:
            analysis["approval"] = {"required": True, "expires_in_minutes": settings.approval_ttl_minutes, "token": approval_token}
            update_investigation_analysis(investigation_id, redact_object({**analysis, "approval": {"required": True, "expires_in_minutes": settings.approval_ttl_minutes}}))

    result = {
        "investigation_id": investigation_id,
        "hostname": identity.get("hostname") or target,
        "target": target,
        "context": objective,
        "identity": identity,
        "profile": profile,
        "environment_classification": classification.__dict__,
        "available_tools": availability,
        "history": history,
        "similar_history": similar_history,
        "playbook": playbook,
        "plans": plans,
        "round_assessments": assessments,
        "evidence": evidence,
        "deterministic_signals": signals,
        "analysis": analysis,
        "corrections": corrections,
        "review": reviewer,
        "approval_token": approval_token,
        "duration_ms": duration_ms,
        "ai_diagnostics": diagnostics,
    }
    if settings.helpdesk_publish_automatically:
        result["helpdesk"] = publish_ticket_report(result, settings=settings)
    return redact_object(result) if not approval_token else {**redact_object({k: v for k, v in result.items() if k != "approval_token"}), "approval_token": approval_token}
