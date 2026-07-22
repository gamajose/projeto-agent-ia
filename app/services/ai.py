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
Você pode sugerir ajustes diretamente relacionados ao alerta apenas em serviços do sistema operacional e serviços internos do site OMD: start, restart, reload, enable e também stop seguido imediatamente de start do mesmo recurso.
Stop isolado é proibido. Quando usar stop/start, o comando deve estar no mesmo campo command e usar && para garantir sequência imediata.
Exemplos permitidos:
- systemctl stop SERVICO && systemctl start SERVICO
- service SERVICO stop && service SERVICO start
- docker exec CONTAINER omd stop SITE && docker exec CONTAINER omd start SITE
Toda ação deve conter validation_command apropriado para confirmar que o recurso subiu.
Se a validação falhar, inclua failure_diagnostics com comandos somente leitura para descobrir o motivo e uma segunda correção segura, quando houver evidência suficiente.
Use somente as evidências fornecidas. Quando não houver evidência suficiente, declare inconclusivo.
Campos obrigatórios: summary, classification, probable_cause, confidence, evidence_used,
recommended_read_only_checks, remediation, validation_steps, ticket_report.
classification deve ser: identical_recurrence, similar_recurrence, new_behavior ou inconclusive.
remediation deve conter objetos com description, command, validation_command, failure_diagnostics, action_type, target e impact.
target deve ser affected ou monitor. action_type deve ser read_only, service_adjustment, omd_adjustment ou config_adjustment.
Comandos de remediation devem ser vazios quando não houver correção segura e diretamente relacionada.
O resumo e o relatório devem ser claros, curtos e objetivos.
""".strip()


def _fallback(message: str) -> dict[str, Any]:
    return {
        "summary": "A coleta foi concluída, mas a análise da IA ficou indisponível.",
        "classification": "inconclusive",
        "probable_cause": message,
        "confidence": 0,
        "evidence_used": [],
        "recommended_read_only_checks": [],
        "remediation": [],
        "validation_steps": [],
        "ticket_report": "Evidências coletadas e registradas. A análise automática da IA não foi concluída.",
        "ai_error": message,
    }


def analyze_with_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    if not settings.gemini_api_key:
        return _fallback("GEMINI_API_KEY não configurada.")

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
                return result
            except json.JSONDecodeError:
                return _fallback("O Gemini respondeu fora do formato JSON esperado.") | {
                    "summary": text[:1000] or "Resposta vazia do Gemini.",
                    "ticket_report": text[:4000],
                    "ai_model": model,
                }
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    return _fallback(last_error or "Nenhum modelo Gemini disponível.")
