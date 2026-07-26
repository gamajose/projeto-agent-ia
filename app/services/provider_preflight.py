from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from enum import StrEnum
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from app.core.settings import Settings, get_settings
from app.services.ai_providers import (
    PROVIDER_LABELS,
    ProviderError,
    _default_omniroute_route,
    _secret,
    current_model_override,
    current_provider_override,
    omniroute_route_options,
    parse_json,
)


class ProviderState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    MISCONFIGURED = "misconfigured"
    DEGRADED = "degraded"
    NOT_CONFIGURED = "not_configured"


STATE_LABELS: dict[ProviderState, str] = {
    ProviderState.AVAILABLE: "disponível",
    ProviderState.UNAVAILABLE: "indisponível",
    ProviderState.MISCONFIGURED: "configuração inválida",
    ProviderState.DEGRADED: "degradado",
    ProviderState.NOT_CONFIGURED: "não configurado",
}


class ProviderPreflight(BaseModel):
    provider: str
    label: str
    state: ProviderState
    model: str = ""
    detail: str
    latency_ms: int | None = Field(default=None, ge=0)
    selectable: bool = False
    valid_routes: tuple[str, ...] = ()
    invalid_routes: tuple[str, ...] = ()

    @property
    def state_label(self) -> str:
        return STATE_LABELS[self.state]


_PROBE_PROMPT = 'Responda somente com o objeto JSON {"preflight":true}.'


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _timeout(settings: Settings) -> float:
    return float(getattr(settings, "ai_preflight_timeout_seconds", 8.0))


def _result(
    provider: str,
    *,
    state: ProviderState,
    model: str,
    detail: str,
    started: float | None = None,
    selectable: bool | None = None,
    valid_routes: tuple[str, ...] = (),
    invalid_routes: tuple[str, ...] = (),
) -> ProviderPreflight:
    return ProviderPreflight(
        provider=provider,
        label=PROVIDER_LABELS[provider],
        state=state,
        model=model,
        detail=detail,
        latency_ms=_elapsed_ms(started) if started is not None else None,
        selectable=state == ProviderState.AVAILABLE if selectable is None else selectable,
        valid_routes=valid_routes,
        invalid_routes=invalid_routes,
    )


def _http_failure(provider: str, model: str, exc: Exception, started: float) -> ProviderPreflight:
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status in {400, 401, 403, 404, 422}:
            return _result(
                provider,
                state=ProviderState.MISCONFIGURED,
                model=model,
                detail=f"A API recusou a configuração (HTTP {status}).",
                started=started,
            )
        return _result(
            provider,
            state=ProviderState.UNAVAILABLE,
            model=model,
            detail=f"O serviço respondeu com erro HTTP {status}.",
            started=started,
        )
    if isinstance(exc, httpx.TimeoutException):
        return _result(
            provider,
            state=ProviderState.UNAVAILABLE,
            model=model,
            detail="Tempo limite excedido ao consultar o serviço.",
            started=started,
        )
    if isinstance(exc, httpx.RequestError):
        return _result(
            provider,
            state=ProviderState.UNAVAILABLE,
            model=model,
            detail="Não foi possível conectar ao endpoint configurado.",
            started=started,
        )
    if isinstance(exc, (json.JSONDecodeError, KeyError, TypeError, ValueError)):
        return _result(
            provider,
            state=ProviderState.DEGRADED,
            model=model,
            detail="O serviço respondeu, mas não retornou JSON válido no formato esperado.",
            started=started,
        )
    return _result(
        provider,
        state=ProviderState.UNAVAILABLE,
        model=model,
        detail=f"Falha inesperada durante o diagnóstico ({type(exc).__name__}).",
        started=started,
    )


def _probe_ollama(settings: Settings, model_name: str | None = None) -> ProviderPreflight:
    model = (model_name or settings.ollama_model or "").strip()
    if not model:
        return _result(
            "ollama",
            state=ProviderState.MISCONFIGURED,
            model="",
            detail="OLLAMA_MODEL não está configurado.",
        )

    started = time.monotonic()
    try:
        tags = httpx.get(
            f"{settings.ollama_base_url.rstrip('/')}/api/tags",
            timeout=_timeout(settings),
        )
        tags.raise_for_status()
        payload = tags.json()
        models = {
            str(value).strip()
            for item in payload.get("models", [])
            if isinstance(item, dict)
            for value in (item.get("name"), item.get("model"))
            if value
        }
        if model not in models:
            return _result(
                "ollama",
                state=ProviderState.MISCONFIGURED,
                model=model,
                detail=f"O serviço respondeu, mas o modelo exato '{model}' não está instalado.",
                started=started,
            )

        response = httpx.post(
            f"{settings.ollama_base_url.rstrip('/')}/api/generate",
            json={
                "model": model,
                "prompt": _PROBE_PROMPT,
                "stream": False,
                "format": "json",
            },
            timeout=_timeout(settings),
        )
        response.raise_for_status()
        generated = response.json()
        parsed = parse_json(str(generated.get("response") or ""))
        if parsed.get("preflight") is not True:
            raise ValueError("resposta de preflight sem confirmação")
        return _result(
            "ollama",
            state=ProviderState.AVAILABLE,
            model=model,
            detail="API, modelo e resposta JSON validados.",
            started=started,
        )
    except Exception as exc:
        return _http_failure("ollama", model, exc, started)


def _configured_omniroute_routes(settings: Settings) -> tuple[str, ...]:
    return tuple(route.model for route in omniroute_route_options(settings))


def _probe_omniroute(settings: Settings, model_name: str | None = None) -> ProviderPreflight:
    try:
        token = _secret(settings, "OMNIROUTE_API_KEY", "omniroute_api_key")
    except Exception:
        return _result(
            "omniroute",
            state=ProviderState.UNAVAILABLE,
            model=(model_name or _default_omniroute_route(settings)),
            detail="Não foi possível consultar o backend de segredos do OmniRoute.",
        )
    selected_model = (model_name or _default_omniroute_route(settings)).strip()
    configured_routes = _configured_omniroute_routes(settings)
    if not token:
        return _result(
            "omniroute",
            state=ProviderState.NOT_CONFIGURED,
            model=selected_model,
            detail="Falta o token local do endpoint (OMNIROUTE_API_KEY).",
        )
    if not selected_model and not configured_routes:
        return _result(
            "omniroute",
            state=ProviderState.MISCONFIGURED,
            model="",
            detail="Configure OMNIROUTE_DEFAULT_ROUTE ou ao menos uma rota em OMNIROUTE_ROUTES.",
        )

    started = time.monotonic()
    try:
        response = httpx.get(
            f"{settings.omniroute_base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {token}"},
            timeout=_timeout(settings),
        )
        response.raise_for_status()
        payload = response.json()
        available_models = {
            str(item.get("id") or "").strip()
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
        candidates = (selected_model,) if model_name and selected_model else configured_routes
        if selected_model and selected_model not in candidates:
            candidates = (selected_model, *candidates)
        valid = tuple(route for route in candidates if route in available_models)
        invalid = tuple(route for route in candidates if route not in available_models)

        if selected_model and selected_model not in available_models:
            return _result(
                "omniroute",
                state=ProviderState.MISCONFIGURED,
                model=selected_model,
                detail=f"A rota/modelo '{selected_model}' não existe no gateway.",
                started=started,
                valid_routes=valid,
                invalid_routes=invalid,
            )
        if not valid:
            return _result(
                "omniroute",
                state=ProviderState.MISCONFIGURED,
                model=selected_model,
                detail="Nenhuma rota configurada no Agent existe no gateway.",
                started=started,
                valid_routes=valid,
                invalid_routes=invalid,
            )
        if invalid:
            return _result(
                "omniroute",
                state=ProviderState.DEGRADED,
                model=selected_model or valid[0],
                detail=f"{len(valid)} rota(s) válida(s); {len(invalid)} rota(s) ausente(s) no gateway.",
                started=started,
                selectable=True,
                valid_routes=valid,
                invalid_routes=invalid,
            )
        return _result(
            "omniroute",
            state=ProviderState.AVAILABLE,
            model=selected_model or valid[0],
            detail="Token, endpoint e rotas configuradas foram validados.",
            started=started,
            valid_routes=valid,
        )
    except Exception as exc:
        return _http_failure("omniroute", selected_model, exc, started)


def _direct_configuration(settings: Settings, provider: str) -> tuple[str | None, str, str]:
    if provider == "gemini":
        return _secret(settings, "GEMINI_API_KEY", "gemini_api_key"), settings.gemini_model, ""
    if provider == "groq":
        return _secret(settings, "GROQ_API_KEY", "groq_api_key"), settings.groq_model, settings.groq_base_url
    if provider == "openrouter":
        return (
            _secret(settings, "OPENROUTER_API_KEY", "openrouter_api_key"),
            settings.openrouter_model,
            settings.openrouter_base_url,
        )
    raise ProviderError(f"Provedor direto desconhecido: {provider}.")


def _probe_direct(settings: Settings, provider: str, model_name: str | None = None) -> ProviderPreflight:
    try:
        api_key, configured_model, base_url = _direct_configuration(settings, provider)
    except Exception:
        return _result(
            provider,
            state=ProviderState.UNAVAILABLE,
            model=model_name or "",
            detail="Não foi possível consultar o backend de segredos do provedor.",
        )
    model = (model_name or configured_model or "").strip()
    if not api_key:
        return _result(
            provider,
            state=ProviderState.NOT_CONFIGURED,
            model=model,
            detail=f"Falta a credencial {provider.upper()}_API_KEY.",
        )
    if not model:
        return _result(
            provider,
            state=ProviderState.MISCONFIGURED,
            model="",
            detail="O modelo do provedor não está configurado.",
        )

    started = time.monotonic()
    try:
        if provider == "gemini":
            response = httpx.post(
                "https://generativelanguage.googleapis.com/v1beta/"
                f"models/{quote(model, safe='')}:generateContent",
                headers={"x-goog-api-key": api_key},
                json={
                    "contents": [{"parts": [{"text": _PROBE_PROMPT}]}],
                    "generationConfig": {
                        "responseMimeType": "application/json",
                        "temperature": 0,
                    },
                },
                timeout=_timeout(settings),
            )
            response.raise_for_status()
            payload = response.json()
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
        else:
            headers = {"Authorization": f"Bearer {api_key}"}
            if provider == "openrouter":
                headers["X-Title"] = settings.openrouter_app_name
                if settings.openrouter_site_url:
                    headers["HTTP-Referer"] = settings.openrouter_site_url
            response = httpx.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": _PROBE_PROMPT}],
                    "temperature": 0,
                    "stream": False,
                    "response_format": {"type": "json_object"},
                },
                timeout=_timeout(settings),
            )
            response.raise_for_status()
            payload = response.json()
            text = payload["choices"][0]["message"]["content"]
        parsed = parse_json(str(text or ""))
        if parsed.get("preflight") is not True:
            raise ValueError("resposta de preflight sem confirmação")
        return _result(
            provider,
            state=ProviderState.AVAILABLE,
            model=model,
            detail="Credencial, modelo e resposta JSON validados.",
            started=started,
        )
    except Exception as exc:
        return _http_failure(provider, model, exc, started)


def preflight_provider(
    provider: str,
    settings: Settings | None = None,
    model_name: str | None = None,
) -> ProviderPreflight:
    settings = settings or get_settings()
    normalized = provider.strip().lower()
    if normalized == "ollama":
        return _probe_ollama(settings, model_name)
    if normalized == "omniroute":
        return _probe_omniroute(settings, model_name)
    if normalized in {"gemini", "groq", "openrouter"}:
        return _probe_direct(settings, normalized, model_name)
    raise ProviderError(f"Provedor desconhecido: {normalized}.")


def preflight_all(settings: Settings | None = None) -> list[ProviderPreflight]:
    settings = settings or get_settings()
    providers = ("gemini", "groq", "openrouter", "ollama", "omniroute")
    with ThreadPoolExecutor(max_workers=len(providers), thread_name_prefix="ai-preflight") as pool:
        return list(pool.map(lambda provider: preflight_provider(provider, settings), providers))


def selected_provider_preflight(settings: Settings | None = None) -> ProviderPreflight:
    settings = settings or get_settings()
    provider = (current_provider_override() or settings.ai_provider or "gemini").strip().lower()
    model = current_model_override()
    return preflight_provider(provider, settings, model)


def require_selected_provider(settings: Settings | None = None) -> ProviderPreflight:
    result = selected_provider_preflight(settings)
    if not result.selectable:
        raise ProviderError(
            f"{result.label} indisponível antes da investigação: {result.detail} "
            "Execute 'agent doctor ai' para o diagnóstico completo."
        )
    return result
