from __future__ import annotations

from typing import Any

import httpx

from app.core.settings import Settings, get_settings
from app.services.redaction import redact_object
from app.services.secrets import get_secret


def publish_ticket_report(result: dict[str, Any], *, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    if not settings.helpdesk_webhook_url:
        return {"status": "disabled", "reason": "HELPDESK_WEBHOOK_URL não configurada"}

    analysis = result.get("analysis") or {}
    payload = redact_object(
        {
            "source": "agent-ia-infra",
            "investigation_id": result.get("investigation_id"),
            "target": result.get("target"),
            "hostname": result.get("hostname"),
            "environment": result.get("environment_classification"),
            "status": analysis.get("status"),
            "confidence": analysis.get("confidence"),
            "probable_cause": analysis.get("probable_cause"),
            "conclusion": analysis.get("conclusion"),
            "ticket_report": analysis.get("ticket_report"),
            "corrections": [
                {
                    "tool": item.get("tool"),
                    "description": item.get("description") or item.get("purpose"),
                    "status": item.get("status"),
                }
                for item in result.get("corrections") or []
            ],
        }
    )
    headers = {"Content-Type": "application/json"}
    token = get_secret("HELPDESK_WEBHOOK_TOKEN", settings.helpdesk_webhook_token, settings=settings)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = httpx.post(settings.helpdesk_webhook_url, json=payload, headers=headers, timeout=20)
        response.raise_for_status()
        return {"status": "published", "status_code": response.status_code}
    except Exception as exc:
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}
