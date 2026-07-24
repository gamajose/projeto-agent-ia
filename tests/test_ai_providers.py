from types import SimpleNamespace

import pytest

from app.services.ai_providers import ProviderError, get_provider, parse_json, provider_status


def settings(**overrides):
    values = {
        "ai_provider": "gemini", "gemini_api_key": "secret-test", "gemini_model": "gemini-test",
        "groq_api_key": None, "groq_model": "llama-test", "groq_base_url": "https://groq.invalid",
        "openrouter_api_key": None, "openrouter_model": "router-test",
        "openrouter_base_url": "https://router.invalid", "openrouter_app_name": "test",
        "openrouter_site_url": None, "ollama_model": "local-test",
        "ollama_base_url": "http://127.0.0.1:11434",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_gemini_is_default():
    provider = get_provider(settings=settings())
    assert provider.name == "gemini"
    assert provider.model == "gemini-test"


def test_provider_requires_its_key():
    with pytest.raises(ProviderError, match="GROQ_API_KEY"):
        get_provider("groq", settings(ai_provider="groq"))


def test_ollama_does_not_require_secret():
    assert get_provider("ollama", settings()).model == "local-test"


def test_status_does_not_expose_keys():
    result = provider_status(settings())
    assert {item["name"] for item in result} == {"gemini", "groq", "openrouter", "ollama"}
    assert "secret-test" not in repr(result)


def test_parse_json_accepts_fenced_response():
    assert parse_json('```json\n{"ok": true}\n```') == {"ok": True}
