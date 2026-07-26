from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from app.core.settings import Settings, get_settings
from app.services.secrets import get_secret


class ApprovalError(ValueError):
    pass


def actions_digest(actions: list[dict[str, Any]]) -> str:
    canonical = json.dumps(actions, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode(value: str) -> bytes:
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    if not hmac.compare_digest(_encode(decoded), value):
        raise ValueError("codificação base64 não canônica")
    return decoded


def _approval_secret(settings: Settings) -> str | None:
    fallback = getattr(settings, "approval_secret", None)
    try:
        return get_secret("APPROVAL_SECRET", fallback, settings=settings)
    except AttributeError:
        return fallback


def create_approval_token(
    investigation_id: str,
    target: str,
    actions: list[dict[str, Any]],
    *,
    ssh_port: int | None = None,
    settings: Settings | None = None,
) -> str | None:
    settings = settings or get_settings()
    secret = _approval_secret(settings)
    if not secret or not actions:
        return None
    now = int(time.time())
    payload = {
        "investigation_id": investigation_id,
        "target": target,
        "actions_digest": actions_digest(actions),
        "iat": now,
        "exp": now + max(1, settings.approval_ttl_minutes) * 60,
    }
    if ssh_port is not None:
        port = int(ssh_port)
        if not 1 <= port <= 65535:
            raise ApprovalError("porta SSH da aprovação deve estar entre 1 e 65535")
        payload["ssh_port"] = port
    encoded = _encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_encode(signature)}"


def verify_approval_token(
    token: str,
    actions: list[dict[str, Any]],
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    secret = _approval_secret(settings)
    if not secret:
        raise ApprovalError("APPROVAL_SECRET não configurado")
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_decode(supplied_signature), expected):
            raise ApprovalError("assinatura da aprovação é inválida")
        payload = json.loads(_decode(encoded))
    except ApprovalError:
        raise
    except Exception as exc:
        raise ApprovalError("token de aprovação inválido") from exc

    if int(payload.get("exp") or 0) < int(time.time()):
        raise ApprovalError("token de aprovação expirado")
    if payload.get("actions_digest") != actions_digest(actions):
        raise ApprovalError("as ações foram alteradas depois da aprovação")
    return payload
