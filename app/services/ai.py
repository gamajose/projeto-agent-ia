from __future__ import annotations

import json
from typing import Any

from google import genai

from app.core.settings import get_settings
from app.services.checkmk_playbooks import build_targeted_plan
from app.services.checkmk_state import build_service_state_report, extract_services

SYSTEM_RULES = """
Você é um analista AIOps de infraestrutura. Responda exclusivamente em JSON válido.
Nunca sugira acesso a banco de dados do cliente. Nunca sugira reboot de host.
Nunca sugira apagar, remover, desinstalar, matar, desabilitar ou mascarar serviços, containers, sites OMD, arquivos ou configurações.
É proibido executar qualquer ação de ciclo de vida em containers: docker start, docker stop, docker restart, docker kill, docker rm, docker rmi ou prune.
Containers podem ser apenas consultados com comandos somente leitura, como docker ps, docker inspect, docker logs e docker events.
Você pode sugerir ajustes diretamente relacionados ao alerta apenas em serviços do sistema operacional e serviços internos do site OMD: start, restart, reload, enable e também stop seguido imediatamente de start do mesmo recurso.
Stop isolado é proibido. Quando usar stop/start, o comando deve estar no mesmo campo command e usar && para garantir sequência imediata.
Toda ação deve conter validation_command apropriado para confirmar que o recurso subiu.
Use somente as evidências fornecidas. Quando não houver evidência suficiente, declare inconclusivo.

REGRAS DE RASTREABILIDADE OBRIGATÓRIAS:
- Nunca declare falha de DNS apenas porque cmk -D, cmk -vvn ou cmk -d falhou.
- Só declare falha de DNS quando existir um comando explícito de resolução, como getent hosts, host, dig ou nslookup, e a saída comprovar a falha.
- Não confunda nome do host Checkmk com endereço usado para conexão SSH.
- Para cada causa provável, informe qual comando produziu a evidência e qual trecho da saída sustenta a conclusão.
- Não repita a mesma causa com frases diferentes.
- Diferencie claramente fatos_observados, hipoteses e conclusao.
- Não diga que uma ação resolveu o problema sem uma validação posterior que demonstre mudança de estado.
- Exit code 0 do cmk -vvn não significa que todos os serviços do host estão OK.
- Use obrigatoriamente service_state_report para identificar serviços antes e depois.
- Respeite resolution: resolved, partially_resolved, not_resolved ou inconclusive.
- Se ainda houver still_affected ou new_issues, nunca informe resolução completa.
- Se o OMD estiver running mas um serviço monitorado continuar CRIT, trate como problema residual separado.
- targeted_plan indica qual coleta deve ser executada; não invente resultado de comandos ainda não executados.

Campos obrigatórios: summary, classification, probable_cause, confidence, facts_observed,
hypotheses, conclusion, evidence_used, recommended_read_only_checks, remediation,
validation_steps, resolution_status, normalized_services, remaining_issues, ticket_report.
classification deve ser: identical_recurrence, similar_recurrence, new_behavior ou inconclusive.
resolution_status deve ser: resolved, partially_resolved, not_resolved ou inconclusive.
remediation deve conter objetos com description, command, validation_command, failure_diagnostics, action_type, target e impact.
target deve ser affected ou monitor. action_type deve ser read_only, service_adjustment, omd_adjustment ou config_adjustment.
Comandos de remediation devem ser vazios quando não houver correção segura e diretamente relacionada.
evidence_used deve conter itens no formato: comando executado | retorno relevante | conclusão suportada.
O resumo e o relatório devem ser claros, técnicos, detalhados e sem afirmações não comprovadas.
""".strip()


def _attach_state_report(result: dict[str, Any], service_state_report: dict[str, Any]) -> dict[str, Any]:
    result["service_state_report"] = service_state_report
    result["resolution"] = service_state_report.get("resolution", "inconclusive")
    result.setdefault("facts_observed", [])
    result.setdefault("hypotheses", [])
    result.setdefault("conclusion", result.get("summary", ""))
    result.setdefault("resolution_status", result["resolution"])
    result.setdefault("normalized_services", service_state_report.get("normalized", []))
    result.setdefault(
        "remaining_issues",
        (service_state_report.get("still_affected") or []) + (service_state_report.get("new_issues") or []),
    )
    if result["resolution"] in {"partially_resolved", "not_resolved", "inconclusive"}:
        result["resolution_status"] = result["resolution"]
    return result


def _deterministic_fallback(
    payload: dict[str, Any],
    message: str,
    service_state_report: dict[str, Any],
) -> dict[str, Any]:
    findings = payload.get("checkmk", {}).get("findings", [])

    for finding in findings:
        if not finding.get("found"):
            continue
        container = str(finding.get("container") or "").strip()
        site = str(finding.get("site") or "").strip()
        omd_status = finding.get("omd_status", {})
        status_text = (str(omd_status.get("stdout") or "") + "\n" + str(omd_status.get("stderr") or "")).lower()

        if container and site and "partially running" in status_text and "automation-helper" in status_text:
            service = "automation-helper"
            command = f"docker exec {container} su - {site} -c 'omd start {service}'"
            validation_command = f"docker exec {container} su - {site} -c 'omd status {service}'"
            status_command = str(omd_status.get("command") or f"docker exec {container} omd status {site}")
            still_affected = service_state_report.get("still_affected") or []
            residual_names = ", ".join(item.get("service", "") for item in still_affected) or "nenhum identificado"
            result = {
                "summary": (
                    "O site OMD apresentou o automation-helper parado. A avaliação final deve considerar separadamente "
                    f"os serviços monitorados residuais: {residual_names}."
                ),
                "classification": "new_behavior",
                "probable_cause": "O serviço interno automation-helper está parado conforme o estado retornado pelo OMD.",
                "confidence": 95,
                "facts_observed": [
                    f"{status_command} retornou automation-helper: stopped.",
                    f"{status_command} retornou Overall state: partially running.",
                ],
                "hypotheses": [
                    "O processo pode ter encerrado após uma falha interna; os logs devem confirmar o motivo."
                ],
                "conclusion": "Há evidência suficiente para iniciar somente o automation-helper e validar novamente.",
                "evidence_used": [
                    f"{status_command} | automation-helper: stopped; Overall state: partially running | serviço interno parado",
                ],
                "recommended_read_only_checks": [
                    validation_command,
                    f"docker exec {container} su - {site} -c 'tail -n 120 ~/var/log/automation-helper.log 2>/dev/null'",
                ],
                "remediation": [{
                    "description": f"Iniciar somente o serviço automation-helper do site OMD {site}, sem reiniciar o container.",
                    "command": command,
                    "validation_command": validation_command,
                    "failure_diagnostics": [
                        validation_command,
                        f"docker exec {container} su - {site} -c 'tail -n 120 ~/var/log/automation-helper.log 2>/dev/null'",
                        f"docker exec {container} su - {site} -c 'ps -ef | grep -F automation-helper | grep -v grep || true'",
                    ],
                    "action_type": "omd_adjustment",
                    "target": "monitor",
                    "impact": "Baixo: inicia somente o serviço interno; o container não é parado nem reiniciado.",
                }],
                "validation_steps": [
                    validation_command,
                    f"docker exec {container} omd status {site}",
                    "Executar novamente cmk -vvn e comparar os serviços antes e depois.",
                ],
                "resolution_status": service_state_report.get("resolution", "not_resolved"),
                "normalized_services": service_state_report.get("normalized", []),
                "remaining_issues": service_state_report.get("still_affected", []),
                "ticket_report": (
                    f"O comando `{status_command}` identificou o automation-helper parado e o site {site} parcialmente ativo. "
                    "Foi autorizada somente a inicialização do serviço interno, com validação obrigatória posterior. "
                    "Alertas residuais devem permanecer registrados separadamente."
                ),
                "ai_error": message,
                "analysis_source": "deterministic_fallback",
            }
            return _attach_state_report(result, service_state_report)

    result = {
        "summary": "A coleta foi concluída, mas não foi possível concluir um diagnóstico automático seguro.",
        "classification": "inconclusive",
        "probable_cause": "As evidências disponíveis não sustentam uma causa raiz única.",
        "confidence": 0,
        "facts_observed": [],
        "hypotheses": [],
        "conclusion": "Diagnóstico inconclusivo; nenhuma correção automática adicional foi autorizada.",
        "evidence_used": [],
        "recommended_read_only_checks": [],
        "remediation": [],
        "validation_steps": [],
        "resolution_status": service_state_report.get("resolution", "inconclusive"),
        "normalized_services": service_state_report.get("normalized", []),
        "remaining_issues": service_state_report.get("still_affected", []),
        "ticket_report": "Evidências coletadas e registradas. Não houve evidência suficiente para uma correção automática segura.",
        "ai_error": message,
        "analysis_source": "deterministic_fallback",
    }
    return _attach_state_report(result, service_state_report)


def analyze_with_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    service_state_report = build_service_state_report(payload)
    detected_services = extract_services(payload.get("checkmk") or {})
    enriched_payload = dict(payload)
    enriched_payload["detected_services"] = detected_services
    enriched_payload["targeted_plan"] = build_targeted_plan(detected_services)
    enriched_payload["service_state_report"] = service_state_report

    settings = get_settings()
    if not settings.gemini_api_key:
        return _deterministic_fallback(
            enriched_payload,
            "GEMINI_API_KEY não configurada.",
            service_state_report,
        )

    client = genai.Client(api_key=settings.gemini_api_key)
    prompt = SYSTEM_RULES + "\n\nEVIDÊNCIAS:\n" + json.dumps(enriched_payload, ensure_ascii=False, default=str)
    models = [settings.gemini_model]
    last_error = ""

    for model in dict.fromkeys(models):
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            text = (response.text or "").strip()
            if text.startswith("```"):
                text = text.strip("`")
                if text.startswith("json"):
                    text = text[4:].lstrip()
            try:
                result = json.loads(text)
                result["ai_model"] = model
                result["analysis_source"] = "gemini"
                return _attach_state_report(result, service_state_report)
            except json.JSONDecodeError:
                last_error = "O Gemini respondeu fora do formato JSON esperado."
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    return _deterministic_fallback(
        enriched_payload,
        last_error or "O modelo configurado em GEMINI_MODEL não está disponível.",
        service_state_report,
    )
