from __future__ import annotations

import json
from typing import Any

from app.core.settings import Settings, get_settings
from app.services.ai_providers import get_provider
from app.services.redaction import redact_object


REVIEW_RULES = """
Você é a segunda IA revisora de uma operação AIOps. Responda somente JSON válido.
Não proponha comandos novos. Verifique se a causa provável e cada ação estão sustentadas
pelas evidências, se o impacto é baixo e se as validações comprovam o resultado funcional.
Aprovação exige concordância explícita com a causa provável e ausência de lacunas críticas.
Formato:
{
  "approved": false,
  "confidence": 0,
  "agrees_with_probable_cause": false,
  "evidence_supported": false,
  "reason": "...",
  "risks": ["..."],
  "action_reviews": [{"tool":"...","approved":false,"reason":"..."}]
}
""".strip()


def review_corrections(
    analysis: dict[str, Any],
    proposals: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    if not proposals:
        return {
            "status": "not_required",
            "approved": False,
            "confidence": 0,
            "reason": "nenhuma ação corretiva foi proposta",
        }

    provider_name = (settings.ai_reviewer_provider or "").strip().lower()
    if not provider_name:
        return {
            "status": "not_configured",
            "approved": False,
            "confidence": 0,
            "reason": "AI_REVIEWER_PROVIDER não configurado",
        }

    payload = redact_object(
        {
            "analysis": analysis,
            "proposals": proposals,
            "evidence": [
                {
                    "tool": item.get("tool"),
                    "command": item.get("command"),
                    "status": item.get("status"),
                    "exit_code": item.get("exit_code"),
                    "stdout": str(item.get("stdout") or "")[-2500:],
                    "stderr": str(item.get("stderr") or "")[-1000:],
                    "validations": item.get("validations") or [],
                }
                for item in evidence[-12:]
            ],
        }
    )
    try:
        reviewer_model = (getattr(settings, "ai_reviewer_model", "") or "").strip() or None
        provider = get_provider(provider_name, settings, reviewer_model)
        result, metadata = provider.generate_json(REVIEW_RULES + "\n\nDADOS:\n" + json.dumps(payload, ensure_ascii=False, default=str))
        confidence = int(result.get("confidence") or 0)
        approved = bool(result.get("approved")) and bool(result.get("agrees_with_probable_cause")) and bool(result.get("evidence_supported")) and confidence >= settings.ai_reviewer_min_confidence
        return {
            **result,
            "status": "approved" if approved else "rejected",
            "approved": approved,
            "confidence": confidence,
            "provider": provider.name,
            "model": provider.model,
            "metadata": metadata,
        }
    except Exception as exc:
        return {
            "status": "error",
            "approved": False,
            "confidence": 0,
            "provider": provider_name,
            "reason": f"{type(exc).__name__}: {exc}",
        }
