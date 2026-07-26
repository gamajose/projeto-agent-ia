from io import StringIO

from rich.console import Console

from app.cli.interactive_menu import _choose_ai
from app.core.settings import Settings
from app.services.provider_preflight import ProviderPreflight, ProviderState


def _settings(**overrides):
    values = {
        "postgres_dsn": "sqlite+pysqlite:///:memory:",
        "omniroute_api_key": "gateway-token",
        "omniroute_default_route": "infra-safe",
        "omniroute_routes": "Infra segura=infra-safe,Análise rápida=infra-fast",
        "gemini_api_key": "gemini-token",
        "gemini_model": "gemini-test",
        "ollama_model": "ollama-test",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _console():
    return Console(file=StringIO(), force_terminal=False, width=140)


def _answers(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr(
        "app.cli.interactive_menu.typer.prompt",
        lambda *args, **kwargs: next(iterator),
    )


def _diagnostics(monkeypatch):
    rows = [
        ProviderPreflight(
            provider=name,
            label=label,
            state=ProviderState.AVAILABLE,
            model=model,
            detail="validado",
            selectable=True,
            valid_routes=("infra-safe", "infra-fast") if name == "omniroute" else (),
        )
        for name, label, model in (
            ("gemini", "Google Gemini", "gemini-test"),
            ("groq", "Groq", "llama-test"),
            ("openrouter", "OpenRouter", "router-test"),
            ("ollama", "Ollama local", "ollama-test"),
            ("omniroute", "OmniRoute", "infra-safe"),
        )
    ]
    monkeypatch.setattr("app.cli.interactive_menu.preflight_all", lambda settings: rows)


def test_menu_selects_route_through_omniroute(monkeypatch):
    _diagnostics(monkeypatch)
    _answers(monkeypatch, [1, 2])

    selected = _choose_ai(_console(), _settings())

    assert selected is not None
    assert selected.source == "gateway"
    assert selected.provider == "omniroute"
    assert selected.model == "infra-fast"
    assert selected.label == "OmniRoute → Análise rápida"


def test_menu_blocks_gateway_without_configured_route(monkeypatch):
    rows = [
        ProviderPreflight(
            provider=name,
            label=name,
            state=ProviderState.MISCONFIGURED if name == "omniroute" else ProviderState.AVAILABLE,
            model="",
            detail="falta rota" if name == "omniroute" else "validado",
            selectable=name != "omniroute",
        )
        for name in ("gemini", "groq", "openrouter", "ollama", "omniroute")
    ]
    monkeypatch.setattr("app.cli.interactive_menu.preflight_all", lambda settings: rows)
    _answers(monkeypatch, [1, 0])
    settings = _settings(omniroute_default_route="", omniroute_routes="", omniroute_model="")

    selected = _choose_ai(_console(), settings)

    assert selected is None


def test_menu_keeps_direct_provider_as_separate_option(monkeypatch):
    _diagnostics(monkeypatch)
    _answers(monkeypatch, [2, 1])

    selected = _choose_ai(_console(), _settings())

    assert selected is not None
    assert selected.source == "direct"
    assert selected.provider == "gemini"
    assert selected.model == "gemini-test"


def test_menu_keeps_ollama_as_local_option(monkeypatch):
    _diagnostics(monkeypatch)
    _answers(monkeypatch, [3])

    selected = _choose_ai(_console(), _settings())

    assert selected is not None
    assert selected.source == "local"
    assert selected.provider == "ollama"
    assert selected.model == "ollama-test"
