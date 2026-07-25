from __future__ import annotations

import json
from typing import Any

from app.core.settings import Settings, get_settings
from app.services.ai_providers import get_provider
from app.services.persistence import get_investigation
from app.services.redaction import redact_object


REPLAY_RULES = """
Você está reanalisando uma investigação AIOps gravada. Não há acesso ao servidor.
Use exclusivamente as evidências persistidas. Responda somente JSON válido.
Formato:
{
  "status":"healthy|attention|critical|inconclusive",
  "confidence":0,
  "summary":"...",
  "facts":["..."],
  "probable_cause":"...",
  "conclusion":"...",
  "recommendations":["..."],
  "evidence_map":[{"conclusion":"...","command":"...","evidence":"..."}],
  "ticket_report":"..."
}
""".strip()


def replay_investigation(
    investigation_id: str,
    *,
    provider_name: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    investigation = get_investigation(investigation_id, include_evidence=True)
    if not investigation:
        raise LookupError("investigação não encontrada")

    provider = get_provider(provider_name, settings)
    payload = redact_object(
        {
            "objective": investigation.get("objective"),
            "target": investigation.get("target"),
            "hostname": investigation.get("hostname"),
            "environment": investigation.get("environment"),
            "profile": investigation.get("profile"),
            "plans": investigation.get("plans"),
            "evidence": investigation.get("evidence"),
            "assessments": investigation.get("assessments"),
            "previous_analysis": investigation.get("analysis"),
        }
    )
    analysis, metadata = provider.generate_json(REPLAY_RULES + "\n\nDADOS:\n" + json.dumps(payload, ensure_ascii=False, default=str))
    return {
        "replay": True,
        "source_investigation_id": investigation_id,
        "provider": provider.name,
        "model": provider.model,
        "analysis": analysis,
        "metadata": metadata,
        "remote_connection_started": False,
    }
