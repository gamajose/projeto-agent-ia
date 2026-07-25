from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.settings import Settings, get_settings


class SecretBackendError(RuntimeError):
    pass


@dataclass
class _CacheEntry:
    expires_at: float
    values: dict[str, Any]


_cache: dict[str, _CacheEntry] = {}
_cache_lock = threading.Lock()


def _vault_cache_key(settings: Settings) -> str:
    return "|".join(
        (
            str(settings.vault_addr or ""),
            str(settings.vault_namespace or ""),
            settings.vault_kv_mount,
            settings.vault_secret_path,
        )
    )


def _vault_values(settings: Settings) -> dict[str, Any]:
    if not settings.vault_addr:
        raise SecretBackendError("VAULT_ADDR não configurado")
    if not settings.vault_token:
        raise SecretBackendError("VAULT_TOKEN não configurado")

    key = _vault_cache_key(settings)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and cached.expires_at > now:
            return dict(cached.values)

    url = (
        f"{settings.vault_addr.rstrip('/')}/v1/"
        f"{settings.vault_kv_mount.strip('/')}/data/"
        f"{settings.vault_secret_path.strip('/')}"
    )
    headers = {"X-Vault-Token": settings.vault_token}
    if settings.vault_namespace:
        headers["X-Vault-Namespace"] = settings.vault_namespace
    try:
        response = httpx.get(
            url,
            headers=headers,
            timeout=15,
            verify=settings.vault_verify_tls,
        )
        response.raise_for_status()
        payload = response.json()
        values = payload.get("data", {}).get("data", {})
        if not isinstance(values, dict):
            raise SecretBackendError("resposta do Vault não contém data.data")
    except SecretBackendError:
        raise
    except Exception as exc:
        raise SecretBackendError(f"falha ao consultar Vault: {type(exc).__name__}: {exc}") from exc

    ttl = max(0, int(settings.vault_cache_seconds))
    with _cache_lock:
        _cache[key] = _CacheEntry(now + ttl, dict(values))
    return dict(values)


def clear_secret_cache() -> None:
    with _cache_lock:
        _cache.clear()


def get_secret(
    name: str,
    fallback: str | None = None,
    *,
    settings: Settings | None = None,
    required: bool = False,
) -> str | None:
    """Retorna um segredo sem expor o valor em mensagens ou logs.

    No backend ``env``, usa o valor já carregado pelo pydantic-settings. No
    backend ``vault``, lê uma chave de um segredo KV v2. Um fallback local pode
    ser usado durante migração, mas o Vault tem precedência quando configurado.
    """
    settings = settings or get_settings()
    backend = (settings.secret_backend or "env").strip().casefold()
    value: Any = fallback
    if backend == "vault":
        values = _vault_values(settings)
        value = values.get(name, fallback)
    elif backend != "env":
        raise SecretBackendError(f"backend de segredos desconhecido: {backend}")

    if value is not None:
        value = str(value)
    if required and not value:
        raise SecretBackendError(f"segredo obrigatório ausente: {name}")
    return value or None


def secret_backend_status(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    backend = (settings.secret_backend or "env").strip().casefold()
    return {
        "backend": backend,
        "configured": backend == "env" or bool(settings.vault_addr and settings.vault_token),
        "vault_addr_configured": bool(settings.vault_addr),
        "vault_token_configured": bool(settings.vault_token),
        "vault_namespace_configured": bool(settings.vault_namespace),
        "path": f"{settings.vault_kv_mount}/{settings.vault_secret_path}" if backend == "vault" else None,
    }
