import pytest

from app.core.settings import Settings
from app.services.ai_providers import (
    OpenAICompatibleProvider,
    ProviderError,
    gateway_status,
    get_provider,
    omniroute_route_options,
    provider_status,
    use_provider,
)


def _settings(**overrides):
    values = {
        "postgres_dsn": "sqlite+pysqlite:///:memory:",
        "omniroute_api_key": "endpoint-secret",
        "omniroute_base_url": "http://127.0.0.1:20128/v1",
        "omniroute_default_route": "combo/infra-safe",
        "omniroute_routes": "Infra segura=combo/infra-safe,Análise rápida=combo/fast",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_omniroute_is_gateway_not_provider_row():
    settings = _settings()
    rows = provider_status(settings)
    status = gateway_status(settings)

    assert all(item["name"] != "omniroute" for item in rows)
    assert status["kind"] == "gateway"
    assert status["label"] == "OmniRoute — gateway centralizado"
    assert status["configured"] is True
    assert status["default_route"] == "combo/infra-safe"


def test_omniroute_routes_are_parsed_for_menu():
    routes = omniroute_route_options(_settings())

    assert [item.label for item in routes] == ["Infra segura", "Análise rápida"]
    assert [item.model for item in routes] == ["combo/infra-safe", "combo/fast"]
    assert routes[0].is_default is True
    assert routes[1].is_default is False


def test_get_provider_uses_route_selected_for_current_operation():
    settings = _settings(omniroute_default_route="")

    provider = get_provider("omniroute", settings, "combo/manual")

    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name == "omniroute"
    assert provider.api_key == "endpoint-secret"
    assert provider.model == "combo/manual"
    assert provider.base_url == "http://127.0.0.1:20128/v1"


def test_context_override_keeps_gateway_route_isolated():
    settings = _settings(omniroute_default_route="")

    with use_provider("omniroute", "combo/session"):
        provider = get_provider(settings=settings)

    assert provider.name == "omniroute"
    assert provider.model == "combo/session"


def test_gateway_requires_token_but_not_fixed_model_in_status():
    settings = _settings(
        omniroute_api_key="endpoint-secret",
        omniroute_default_route="",
        omniroute_routes="",
        omniroute_model="",
    )

    assert gateway_status(settings)["configured"] is True
    with pytest.raises(ProviderError, match="Selecione uma rota/modelo"):
        get_provider("omniroute", settings)


def test_legacy_omniroute_model_remains_compatible():
    settings = _settings(
        omniroute_default_route="",
        omniroute_routes="",
        omniroute_model="legacy/route",
    )

    provider = get_provider("omniroute", settings)
    assert provider.model == "legacy/route"
