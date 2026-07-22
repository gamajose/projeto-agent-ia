from __future__ import annotations

import json
from typing import Any

from google import genai

from app.core.settings import get_settings

SYSTEM_RULES = """
Você é um analista AIOps de infraestrutura. Responda exclusivamente em JSON válido.
Nunca sugira acesso a banco de dados do cliente. Nunca sugira reboot de host.
Diferencie restart de serviço, container e site OMD. Ações de impacto exigem aprovação humana.
Use somente as evidências fornecidas. Quando não houver evidência suficiente, declare inconclusivo.
Campos obrigatórios: summary, classification, probable_cause, confidence, evidence_used,
recommended_read_only_checks, remediation, validation_steps, ticket_report.
classification deve ser: identical_recurrence, similar_recurrence, new_behavior ou inconclusive.
remediation deve conter objetos com description, command, action_type e impact.
Comandos de remediation devem ser vazios quando não houver correção segura e diretamente relacionada.
""".strip()


def analyze_with_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    if not settings.gemini_api_key:
        return {
            "summary": "Gemini não configurado.",
            "classification": "inconclusive",
            "probable_cause": "Análise automática indisponível.",
            "confidence": 0,
            "evidence_used": [],
            "recommended_read_only_checks": [],
            "remediation": [],
            "validation_steps": [],
            "ticket_report": "Diagnóstico coletado, porém sem análise Gemini.",
        }

    client = genai.Client(api_key=settings.gemini_api_key)
    prompt = SYSTEM_RULES + "\n\nEVIDÊNCIAS:\n" + json.dumps(payload, ensure_ascii=False, default=str)
    response = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
    text = (response.text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].lstrip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "summary": text[:1000] or "Resposta vazia do Gemini.",
            "classification": "inconclusive",
            "probable_cause": "Resposta do modelo não estava em JSON válido.",
            "confidence": 0,
            "evidence_used": [],
            "recommended_read_only_checks": [],
            "remediation": [],
            "validation_steps": [],
            "ticket_report": text[:4000],
        }
