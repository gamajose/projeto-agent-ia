from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
from typer.testing import CliRunner

from app.cli.agent import doctor_app
from app.core.policies import EnvironmentType
from app.core.settings import Settings
from app.services.ai_providers import ProviderError
from app.services.provider_preflight import (
    ProviderPreflight,
    ProviderState,
    preflight_provider,
)


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.request = httpx.Request("GET", "http://service.invalid")

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "erro",
                request=self.request,
                response=httpx.Response(self.status_code, request=self.request),
            )


def _settings(**overrides) -> Settings:
    values = {
        "postgres_dsn": "sqlite+pysqlite:///:memory:",
        "ai_preflight_timeout_seconds": 2,
        "ollama_base_url": "http://ollama.invalid",
        "ollama_model": "gemma3:4b",
        "omniroute_api_key": "endpoint-secret",
        "omniroute_base_url": "http://omniroute.invalid/v1",
        "omniroute_default_route": "auto",
        "omniroute_routes": "Balanceado=auto,Código=auto/coding",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_ollama_available_only_when_exact_model_and_json_probe_work():
    tags = FakeResponse({"models": [{"name": "gemma3:4b"}]})
    generation = FakeResponse({"response": '{"preflight": true}'})

    with patch("app.services.provider_preflight.httpx.get", return_value=tags), patch(
        "app.services.provider_preflight.httpx.post",
        return_value=generation,
    ):
        result = preflight_provider("ollama", _settings())

    assert result.state == ProviderState.AVAILABLE
    assert result.selectable is True
    assert result.model == "gemma3:4b"


def test_ollama_reports_missing_exact_model_without_generation_call():
    tags = FakeResponse({"models": [{"name": "gemma3:12b"}]})

    with patch("app.services.provider_preflight.httpx.get", return_value=tags), patch(
        "app.services.provider_preflight.httpx.post"
    ) as generation:
        result = preflight_provider("ollama", _settings())

    assert result.state == ProviderState.MISCONFIGURED
    assert result.selectable is False
    assert "não está instalado" in result.detail
    generation.assert_not_called()


def test_ollama_reports_unavailable_service_without_raw_traceback():
    request = httpx.Request("GET", "http://ollama.invalid/api/tags")
    with patch(
        "app.services.provider_preflight.httpx.get",
        side_effect=httpx.ConnectError("connection refused secret-value", request=request),
    ):
        result = preflight_provider("ollama", _settings())

    assert result.state == ProviderState.UNAVAILABLE
    assert "secret-value" not in result.detail


def test_omniroute_requires_endpoint_token_before_network():
    with patch("app.services.provider_preflight.httpx.get") as request:
        result = preflight_provider(
            "omniroute",
            _settings(omniroute_api_key=None),
        )

    assert result.state == ProviderState.NOT_CONFIGURED
    assert result.selectable is False
    assert "OMNIROUTE_API_KEY" in result.detail
    request.assert_not_called()


def test_omniroute_requires_at_least_one_configured_route():
    with patch("app.services.provider_preflight.httpx.get") as request:
        result = preflight_provider(
            "omniroute",
            _settings(
                omniroute_default_route="",
                omniroute_routes="",
                omniroute_model="",
            ),
        )

    assert result.state == ProviderState.MISCONFIGURED
    assert result.selectable is False
    request.assert_not_called()


def test_omniroute_rejects_route_missing_from_models_endpoint():
    response = FakeResponse({"data": [{"id": "auto/coding"}]})
    with patch("app.services.provider_preflight.httpx.get", return_value=response):
        result = preflight_provider("omniroute", _settings(), "auto")

    assert result.state == ProviderState.MISCONFIGURED
    assert result.selectable is False
    assert "não existe" in result.detail


def test_omniroute_accepts_route_published_by_models_endpoint():
    response = FakeResponse({"data": [{"id": "auto/coding"}, {"id": "auto/fast"}]})
    settings = _settings(
        omniroute_default_route="auto/coding",
        omniroute_routes="Código=auto/coding,Rápido=auto/fast",
    )
    with patch("app.services.provider_preflight.httpx.get", return_value=response):
        result = preflight_provider("omniroute", settings)

    assert result.state == ProviderState.AVAILABLE
    assert result.selectable is True
    assert result.valid_routes == ("auto/coding", "auto/fast")


def test_omniroute_reports_unavailable_gateway():
    request = httpx.Request("GET", "http://omniroute.invalid/v1/models")
    with patch(
        "app.services.provider_preflight.httpx.get",
        side_effect=httpx.ConnectError("refused", request=request),
    ):
        result = preflight_provider("omniroute", _settings())

    assert result.state == ProviderState.UNAVAILABLE
    assert result.selectable is False


def test_doctor_ai_masks_credentials_and_renders_state():
    diagnostic = ProviderPreflight(
        provider="omniroute",
        label="OmniRoute",
        state=ProviderState.AVAILABLE,
        model="auto",
        detail="Token, endpoint e rota validados.",
        latency_ms=12,
        selectable=True,
    )
    runner = CliRunner()

    with patch("app.cli.agent.preflight_all", return_value=[diagnostic]):
        result = runner.invoke(doctor_app, [])

    assert result.exit_code == 0
    assert "disponível" in result.stdout
    assert "auto" in result.stdout
    assert "endpoint-secret" not in result.stdout
    assert "Nenhuma senha, token ou API key é exibida" in result.stdout


def test_run_target_stops_before_resolution_and_ssh_when_provider_fails():
    settings = _settings()
    with patch(
        "app.services.runner.require_selected_provider",
        side_effect=ProviderError("provedor indisponível"),
    ), patch("app.services.runner.resolve_target") as resolver, patch(
        "app.services.runner.build_executor"
    ) as executor:
        from app.services.runner import run_target

        with pytest.raises(ProviderError, match="provedor indisponível"):
            run_target(
                "192.0.2.10",
                "validar",
                environment=EnvironmentType.TRAINING,
                settings=settings,
            )

    resolver.assert_not_called()
    executor.assert_not_called()
