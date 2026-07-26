from __future__ import annotations

import json
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator, Protocol

import httpx
from google import genai
from google.genai import types

from app.core.settings import Settings, get_settings
from app.services.secrets import get_secret


class ProviderError(RuntimeError):
    pass


class AIProvider(Protocol):
    name: str
    model: str

    def generate_json(self, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]: ...


def parse_json(text: str) -> dict[str, Any]:
    value = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.I)
    try:
        result = json.loads(value)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", value, flags=re.S)
        if not match:
            raise
        result = json.loads(match.group(0))
    if not isinstance(result, dict):
        raise ValueError("A resposta da IA não é um objeto JSON.")
    return result


@dataclass
class GeminiProvider:
    api_key: str
    model: str
    name: str = "gemini"

    def generate_json(self, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
        response = genai.Client(api_key=self.api_key).models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.1),
        )
        text = response.text or ""
        return parse_json(text), {"response_chars": len(text)}


@dataclass
class OpenAICompatibleProvider:
    name: str
    api_key: str
    model: str
    base_url: str
    headers: dict[str, str] | None = None

    def generate_json(self, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
        response = httpx.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", **(self.headers or {})},
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            },
            timeout=90,
        )
        response.raise_for_status()
        text = response.json()["choices"][0]["message"]["content"] or ""
        return parse_json(text), {"response_chars": len(text), "status_code": response.status_code}


@dataclass
class OllamaProvider:
    model: str
    base_url: str
    name: str = "ollama"

    def generate_json(self, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
        response = httpx.post(
            f"{self.base_url.rstrip('/')}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=180,
        )
        response.raise_for_status()
        text = response.json().get("response") or ""
        return parse_json(text), {"response_chars": len(text), "status_code": response.status_code}


@dataclass(frozen=True)
class GatewayRoute:
    label: str
    model: str
    is_default: bool = False


PROVIDER_LABELS = {
    "gemini": "Google Gemini",
    "groq": "Groq (Llama)",
    "openrouter": "OpenRouter",
    "ollama": "Ollama local",
    "omniroute": "OmniRoute",
}

_PROVIDER_OVERRIDE: ContextVar[str | None] = ContextVar("agent_ai_provider_override", default=None)
_MODEL_OVERRIDE: ContextVar[str | None] = ContextVar("agent_ai_model_override", default=None)


@contextmanager
def use_provider(name: str | None, model: str | None = None) -> Iterator[None]:
    """Seleciona backend e modelo/rota apenas no contexto atual."""
    provider_token = _PROVIDER_OVERRIDE.set((name or "").strip().lower() or None)
    model_token = _MODEL_OVERRIDE.set((model or "").strip() or None)
    try:
        yield
    finally:
        _MODEL_OVERRIDE.reset(model_token)
        _PROVIDER_OVERRIDE.reset(provider_token)


def current_provider_override() -> str | None:
    return _PROVIDER_OVERRIDE.get()


def current_model_override() -> str | None:
    return _MODEL_OVERRIDE.get()


def _secret(settings: Settings, name: str, attribute: str) -> str | None:
    fallback = getattr(settings, attribute, None)
    try:
        return get_secret(name, fallback, settings=settings)
    except AttributeError:
        return fallback


def direct_provider_status(settings: Settings | None = None) -> list[dict[str, Any]]:
    settings = settings or get_settings()
    return [
        {
            "kind": "provider",
            "source": "direct",
            "name": "gemini",
            "label": PROVIDER_LABELS["gemini"],
            "model": settings.gemini_model,
            "configured": bool(_secret(settings, "GEMINI_API_KEY", "gemini_api_key")),
        },
        {
            "kind": "provider",
            "source": "direct",
            "name": "groq",
            "label": PROVIDER_LABELS["groq"],
            "model": settings.groq_model,
            "configured": bool(_secret(settings, "GROQ_API_KEY", "groq_api_key")),
        },
        {
            "kind": "provider",
            "source": "direct",
            "name": "openrouter",
            "label": PROVIDER_LABELS["openrouter"],
            "model": settings.openrouter_model,
            "configured": bool(_secret(settings, "OPENROUTER_API_KEY", "openrouter_api_key")),
        },
    ]


def local_provider_status(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    return {
        "kind": "provider",
        "source": "local",
        "name": "ollama",
        "label": PROVIDER_LABELS["ollama"],
        "model": settings.ollama_model,
        "configured": True,
    }


def provider_status(settings: Settings | None = None) -> list[dict[str, Any]]:
    """Lista apenas provedores/modelos reais; gateways são consultados separadamente."""
    settings = settings or get_settings()
    return [*direct_provider_status(settings), local_provider_status(settings)]


def _default_omniroute_route(settings: Settings) -> str:
    return (
        getattr(settings, "omniroute_default_route", "")
        or getattr(settings, "omniroute_model", "")
        or ""
    ).strip()


def omniroute_route_options(settings: Settings | None = None) -> list[GatewayRoute]:
    settings = settings or get_settings()
    default_route = _default_omniroute_route(settings)
    routes: list[GatewayRoute] = []
    seen: set[str] = set()

    for raw_item in re.split(r"[,\n]", getattr(settings, "omniroute_routes", "") or ""):
        item = raw_item.strip()
        if not item:
            continue
        if "=" in item:
            label, model = (part.strip() for part in item.split("=", 1))
        elif "|" in item:
            label, model = (part.strip() for part in item.split("|", 1))
        else:
            label = model = item
        if not model or model in seen:
            continue
        seen.add(model)
        routes.append(GatewayRoute(label=label or model, model=model, is_default=model == default_route))

    if default_route and default_route not in seen:
        routes.insert(0, GatewayRoute(label=default_route, model=default_route, is_default=True))
    return routes


def gateway_status(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    return {
        "kind": "gateway",
        "source": "gateway",
        "name": "omniroute",
        "label": "OmniRoute — gateway centralizado",
        "configured": bool(_secret(settings, "OMNIROUTE_API_KEY", "omniroute_api_key")),
        "base_url": settings.omniroute_base_url,
        "default_route": _default_omniroute_route(settings),
        "routes": omniroute_route_options(settings),
    }


def get_provider(
    name: str | None = None,
    settings: Settings | None = None,
    model_name: str | None = None,
) -> AIProvider:
    settings = settings or get_settings()
    selected = (name or current_provider_override() or settings.ai_provider or "gemini").strip().lower()
    selected_model = (model_name or current_model_override() or "").strip()
    gemini_key = _secret(settings, "GEMINI_API_KEY", "gemini_api_key")
    groq_key = _secret(settings, "GROQ_API_KEY", "groq_api_key")
    openrouter_key = _secret(settings, "OPENROUTER_API_KEY", "openrouter_api_key")
    omniroute_key = _secret(settings, "OMNIROUTE_API_KEY", "omniroute_api_key")

    if selected == "gemini" and gemini_key:
        return GeminiProvider(gemini_key, selected_model or settings.gemini_model)
    if selected == "groq" and groq_key:
        return OpenAICompatibleProvider(
            "groq", groq_key, selected_model or settings.groq_model, settings.groq_base_url
        )
    if selected == "openrouter" and openrouter_key:
        headers = {"X-Title": settings.openrouter_app_name}
        if settings.openrouter_site_url:
            headers["HTTP-Referer"] = settings.openrouter_site_url
        return OpenAICompatibleProvider(
            "openrouter",
            openrouter_key,
            selected_model or settings.openrouter_model,
            settings.openrouter_base_url,
            headers,
        )
    if selected == "ollama":
        return OllamaProvider(selected_model or settings.ollama_model, settings.ollama_base_url)

    if selected == "omniroute" and omniroute_key:
        route = selected_model or _default_omniroute_route(settings)
        if not route:
            raise ProviderError(
                "Selecione uma rota/modelo do OmniRoute no menu ou configure OMNIROUTE_DEFAULT_ROUTE."
            )
        return OpenAICompatibleProvider(
            "omniroute",
            omniroute_key,
            route,
            settings.omniroute_base_url,
        )
    if selected not in PROVIDER_LABELS:
        raise ProviderError(f"Provedor desconhecido: {selected}.")
    if selected == "omniroute":
        raise ProviderError("OMNIROUTE_API_KEY não configurada.")
    raise ProviderError(f"{selected.upper()}_API_KEY não configurada.")
