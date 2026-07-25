from app.core.settings import Settings
from app.services.ai_providers import current_provider_override, get_provider, use_provider


def test_provider_override_is_scoped():
    settings = Settings(postgres_dsn="sqlite+pysqlite:///:memory:", ai_provider="gemini")
    assert current_provider_override() is None
    with use_provider("ollama"):
        assert current_provider_override() == "ollama"
        assert get_provider(settings=settings).name == "ollama"
    assert current_provider_override() is None
