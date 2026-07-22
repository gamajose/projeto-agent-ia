from __future__ import annotations

import json
from typing import Any

from google import genai

from app.core.settings import get_settings

SYSTEM_RULES = """
Você é um analista AIOps de infraestrutura. Responda exclusivamente em JSON válido.
Nunca sugira acesso a banco de dados do cliente. Nunca sugira reboot de host.
Nunca sugira apagar, remover, desinstalar, matar, desabilitar ou mascarar serviços, containers, sites OMD, arquivos ou configurações.
É proibido executar qualquer ação de ciclo de vida em containers: docker start, docker stop, docker restart, docker kill, docker rm, docker rmi ou prune.
Containers podem ser apenas consultados com comandos somente leitura, como docker ps, docker inspect, docker logs e docker events.
Você pode iniciar ou reiniciar serviços internos do site OMD sem reiniciar o container, executando o comando como usuário do site.
Exemplo: docker exec CONTAINER su - SITE -c 'omd start SERVICO'.
Para um serviço OMD parado, prefira iniciar somente o serviço afetado, e não o site inteiro.
Você pode sugerir ajustes diretamente relacionados ao alerta apenas em serviços do sistema operacional e serviços internos do site OMD: start, restart, reload, enable e também stop seguido imediatamente de start do mesmo recurso.
Stop isolado é proibido. Quando usar stop/start, o comando deve estar no mesmo campo command e usar && para garantir sequência imediata.
Toda ação deve conter validation_command apropriado para confirmar que o recurso subiu.
Se a ação falhar, colete status e logs do serviço antes de concluir o diagnóstico.
Use somente as evidências fornecidas. Quando não houver evidência suficiente, declare inconclusivo.
Campos obrigatórios: summary, classification, probable_cause, confidence, evidence_used,
recommended_read_only_checks, remediation, validation_steps, ticket_report.
classification deve ser: identical_recurrence, similar_recurrence, new_behavior ou inconclusive.
remediation deve conter objetos com description, command, validation_command, failure_diagnostics, action_type, target e impact.
target deve ser affected ou monitor. action_type deve ser read_only, service_adjustment, omd_adjustment ou config_adjustment.
Comandos de remediation devem ser vazios quando não houver correção segura e diretamente relacionada.
O resumo e o relatório devem ser claros, curtos e objetivos.
""".strip()


def _deterministic_fallback(payload: dict[str, Any], message: str) -> dict[str, Any]:
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
            command = f"docker exec {container} su - {site} -c 'omd start automation-helper'"
            validation_command = f"docker exec {container} su - {site} -c 'omd status automation-helper'"
            log_command = (
                f"docker exec {container} su - {site} -c "
                "'tail -n 150 ~/var/log/automation-helper.log 2>/dev/null'"
            )
            return {
                "summary": "O site OMD está parcialmente ativo porque o serviço automation-helper está parado.",
                "classification": "identical_recurrence",
                "probable_cause": "O automation-helper do site OMD não está em execução, mantendo o site parcialmente ativo e o healthcheck do container em estado unhealthy.",
                "confidence": 98,
                "evidence_used": [
                    f"Site OMD {site} com estado partially running.",
                    "Serviço automation-helper identificado como stopped.",
                    "Healthcheck do container reportando unhealthy por falha no estado do site OMD.",
                ],
                "recommended_read_only_checks": [
                    validation_command,
                    log_command,
                ],
                "remediation": [
                    {
                        "description": f"Iniciar somente o serviço automation-helper do site OMD {site}, sem reiniciar o container.",
                        "command": command,
                        "validation_command": validation_command,
                        "failure_diagnostics": [validation_command, log_command],
                        "action_type": "omd_adjustment",
                        "target": "monitor",
                        "impact": "Baixo: inicia apenas o automation-helper dentro do site OMD; não reinicia o container.",
                    }
                ],
                "validation_steps": [
                    validation_command,
                    f"docker exec {container} omd status {site}",
                    "Executar novamente cmk -vvn para confirmar a normalização do monitoramento.",
                ],
                "ticket_report": (
                    f"Identificamos que o site OMD {site} estava parcialmente ativo devido ao serviço "
                    "automation-helper parado. Foi iniciado somente o serviço afetado dentro do site OMD, "
                    "sem reiniciar o container, seguido da validação do serviço, do site e do monitoramento."
                ),
                "ai_error": message,
                "analysis_source": "deterministic_fallback",
            }

    return {
        "summary": "A coleta foi concluída, mas não foi possível concluir um diagnóstico automático seguro.",
        "classification": "inconclusive",
        "probable_cause": message,
        "confidence": 0,
        "evidence_used": [],
        "recommended_read_only_checks": [],
        "remediation": [],
        "validation_steps": [],
        "ticket_report": "Evidências coletadas e registradas. Não houve evidência suficiente para uma correção automática segura.",
        "ai_error": message,
        "analysis_source": "deterministic_fallback",
    }


def analyze_with_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    if not settings.gemini_api_key:
        return _deterministic_fallback(payload, "GEMINI_API_KEY não configurada.")

    client = genai.Client(api_key=settings.gemini_api_key)
    prompt = SYSTEM_RULES + "\n\nEVIDÊNCIAS:\n" + json.dumps(payload, ensure_ascii=False, default=str)
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
                return result
            except json.JSONDecodeError:
                last_error = "O Gemini respondeu fora do formato JSON esperado."
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    return _deterministic_fallback(payload, last_error or "Nenhum modelo Gemini disponível.")
