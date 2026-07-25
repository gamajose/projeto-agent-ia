from app.core.settings import Settings
from app.services.ai_providers import OpenAICompatibleProvider, get_provider, provider_status


def _settings(**overrides):
    values = {
        "postgres_dsn": "sqlite+pysqlite:///:memory:",
        "omniroute_api_key": "endpoint-secret",
        "omniroute_model": "combo/infra-safe",
        "omniroute_base_url": "http://127.0.0.1:20128/v1",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_omniroute_appears_configured_in_provider_status():
    rows = provider_status(_settings())
    omniroute = next(item for item in rows if item["name"] == "omniroute")

    assert omniroute["label"] == "OmniRoute gateway"
    assert omniroute["model"] == "combo/infra-safe"
    assert omniroute["configured"] is True


def test_get_provider_builds_openai_compatible_omniroute():
    provider = get_provider("omniroute", _settings())

    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name == "omniroute"
    assert provider.api_key == "endpoint-secret"
    assert provider.model == "combo/infra-safe"
    assert provider.base_url == "http://127.0.0.1:20128/v1"
