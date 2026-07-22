from __future__ import annotations

import json
from typing import Any

from google import genai

from app.core.settings import get_settings
from app.services.checkmk_state import build_service_state_report

SYSTEM_RULES = """
Você é um analista AIOps de infraestrutura. Responda exclusivamente em JSON válido.
Nunca sugira acesso a banco de dados do cliente. Nunca sugira reboot de host.
Nunca sugira apagar, remover, desinstalar, matar, desabilitar ou mascarar serviços, containers, sites OMD, arquivos ou configurações.
É proibido executar qualquer ação de ciclo de vida em containers: docker start, docker stop, docker restart, docker kill, docker rm, docker rmi ou prune.
Containers podem ser apenas consultados com comandos somente leitura, como docker ps, docker inspect, docker logs e docker events.
Você pode sugerir ajustes diretamente relacionados ao alerta apenas em serviços do sistema operacional e serviços internos do site OMD: start, restart, reload, enable e também stop seguido imediatamente de start do mesmo recurso.
Stop isolado é proibido. Quando usar stop/start, o comando deve estar no mesmo campo command e usar && para garantir sequência imediata.
Exemplos permitidos:
- systemctl stop SERVICO && systemctl start SERVICO
- service SERVICO stop && service SERVICO start
- docker exec CONTAINER su - SITE -c 'omd start SERVICO'
- docker exec CONTAINER su - SITE -c 'omd restart SERVICO'
- docker exec CONTAINER omd stop SITE && docker exec CONTAINER omd start SITE
Toda ação deve conter validation_command apropriado para confirmar que o recurso subiu.
Se a validação falhar, inclua failure_diagnostics com comandos somente leitura para descobrir o motivo e uma segunda correção segura, quando houver evidência suficiente.
Use somente as evidências fornecidas. Quando não houver evidência suficiente, declare inconclusivo.

REGRAS DE RASTREABILIDADE OBRIGATÓRIAS:
- Nunca declare falha de DNS apenas porque cmk -D, cmk -vvn ou cmk -d falhou.
- Só declare falha de DNS quando existir um comando explícito de resolução, como getent hosts, host, dig ou nslookup, e a saída desse comando comprovar a falha.
- Não confunda nome do host Checkmk com endereço usado para conexão SSH.
- Para cada causa provável, informe qual comando produziu a evidência e qual trecho da saída sustenta a conclusão.
- Não repita a mesma causa com frases diferentes.
- Diferencie claramente: fato observado, interpretação e ação executada.
- Não diga que uma ação resolveu o problema sem uma validação posterior que demonstre mudança de estado.
- Exit code 0 do cmk -vvn não significa que todos os serviços do host estão OK.
- Use obrigatoriamente o bloco service_state_report para identificar serviços antes e depois.
- Respeite o campo resolution de service_state_report: resolved, partially_resolved, not_resolved ou inconclusive.
- Se ainda houver itens em still_affected ou new_issues, nunca informe resolução completa.
- Se o OMD estiver running mas um serviço monitorado continuar CRIT, trate como problema residual separado.
- Cite nominalmente os serviços normalizados e os que permaneceram afetados.

Campos obrigatórios: summary, classification, probable_cause, confidence, evidence_used,
recommended_read_only_checks, remediation, validation_steps, ticket_report.
classification deve ser: identical_recurrence, similar_recurrence, new_behavior ou inconclusive.
remediation deve conter objetos com description, command, validation_command, failure_diagnostics, action_type, target e impact.
target deve ser affected ou monitor. action_type deve ser read_only, service_adjustment, omd_adjustment ou config_adjustment.
Comandos de remediation devem ser vazios quando não houver correção segura e diretamente relacionada.
evidence_used deve conter itens no formato: comando executado | retorno relevante | conclusão suportada.
O resumo e o relatório devem ser claros, técnicos, detalhados e sem afirmações não comprovadas.
""".strip()


def _attach_state_report(result: dict[str, Any], service_state_report: dict[str, Any]) -> dict[str, Any]:
    result["service_state_report"] = service_state_report
    result["resolution"] = service_state_report.get("resolution", "inconclusive")
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
        status_text = (
            str(omd_status.get("stdout") or "")
            + "\n"
            + str(omd_status.get("stderr") or "")
        ).lower()

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
                "probable_cause": (
                    f"Fato observado: o comando `{status_command}` retornou `automation-helper: stopped` "
                    "e `Overall state: partially running`. Interpretação: o serviço interno automation-helper "
                    "não está em execução. Nenhuma conclusão de DNS é suportada por essa evidência."
                ),
                "confidence": 95,
                "evidence_used": [
                    f"{status_command} | automation-helper: stopped; Overall state: partially running | serviço interno parado",
                ],
                "recommended_read_only_checks": [
                    validation_command,
                    f"docker exec {container} su - {site} -c 'tail -n 120 ~/var/log/automation-helper.log 2>/dev/null'",
                ],
                "remediation": [
                    {
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
                        "impact": "Baixo: inicia somente o serviço interno automation-helper; o container não é parado nem reiniciado.",
                    }
                ],
                "validation_steps": [
                    validation_command,
                    f"docker exec {container} omd status {site}",
                    "Executar novamente cmk -vvn e comparar os serviços CRIT antes e depois.",
                    "Confirmar separadamente se ainda existe serviço Process automation helpers em CRIT.",
                ],
                "ticket_report": (
                    f"O comando `{status_command}` identificou o serviço automation-helper parado e o site OMD {site} "
                    "em estado parcialmente ativo. Foi executado o início somente desse serviço interno, sem reinício do "
                    "container. Em seguida foram executadas validações do serviço, do estado global do OMD e dos serviços "
                    f"monitorados. Resultado de resolução: {service_state_report.get('resolution', 'inconclusive')}."
                ),
                "ai_error": message,
                "analysis_source": "deterministic_fallback",
            }
            return _attach_state_report(result, service_state_report)

    result = {
        "summary": "A coleta foi concluída, mas não foi possível concluir um diagnóstico automático seguro.",
        "classification": "inconclusive",
        "probable_cause": (
            "A IA externa ficou indisponível e as evidências locais não corresponderam a uma regra determinística segura. "
            f"Erro da IA externa: {message}"
        ),
        "confidence": 0,
        "evidence_used": [],
        "recommended_read_only_checks": [],
        "remediation": [],
        "validation_steps": [],
        "ticket_report": "Evidências coletadas e registradas. Não houve evidência suficiente para uma correção automática segura.",
        "ai_error": message,
        "analysis_source": "deterministic_fallback",
    }
    return _attach_state_report(result, service_state_report)


def analyze_with_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    service_state_report = build_service_state_report(payload)
    enriched_payload = dict(payload)
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
    models = [settings.gemini_model, "gemini-3.6-flash", "gemini-3.5-flash"]
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
        last_error or "Nenhum modelo Gemini disponível.",
        service_state_report,
    )
