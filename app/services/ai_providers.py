from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from google import genai
from google.genai import types

from app.core.settings import Settings, get_settings


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
            model=self.model, contents=prompt,
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
            json={"model": self.model, "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.1, "response_format": {"type": "json_object"}},
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


PROVIDER_LABELS = {"gemini": "Google Gemini", "groq": "Groq (Llama)",
                   "openrouter": "OpenRouter", "ollama": "Ollama local"}


def provider_status(settings: Settings | None = None) -> list[dict[str, Any]]:
    settings = settings or get_settings()
    return [
        {"name": "gemini", "label": PROVIDER_LABELS["gemini"], "model": settings.gemini_model, "configured": bool(settings.gemini_api_key)},
        {"name": "groq", "label": PROVIDER_LABELS["groq"], "model": settings.groq_model, "configured": bool(settings.groq_api_key)},
        {"name": "openrouter", "label": PROVIDER_LABELS["openrouter"], "model": settings.openrouter_model, "configured": bool(settings.openrouter_api_key)},
        {"name": "ollama", "label": PROVIDER_LABELS["ollama"], "model": settings.ollama_model, "configured": True},
    ]


def get_provider(name: str | None = None, settings: Settings | None = None) -> AIProvider:
    settings = settings or get_settings()
    selected = (name or settings.ai_provider or "gemini").strip().lower()
    if selected == "gemini" and settings.gemini_api_key:
        return GeminiProvider(settings.gemini_api_key, settings.gemini_model)
    if selected == "groq" and settings.groq_api_key:
        return OpenAICompatibleProvider("groq", settings.groq_api_key, settings.groq_model, settings.groq_base_url)
    if selected == "openrouter" and settings.openrouter_api_key:
        headers = {"X-Title": settings.openrouter_app_name}
        if settings.openrouter_site_url:
            headers["HTTP-Referer"] = settings.openrouter_site_url
        return OpenAICompatibleProvider("openrouter", settings.openrouter_api_key, settings.openrouter_model,
                                        settings.openrouter_base_url, headers)
    if selected == "ollama":
        return OllamaProvider(settings.ollama_model, settings.ollama_base_url)
    if selected not in PROVIDER_LABELS:
        raise ProviderError(f"Provedor desconhecido: {selected}.")
    raise ProviderError(f"{selected.upper()}_API_KEY não configurada.")
