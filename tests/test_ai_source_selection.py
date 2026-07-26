from io import StringIO

from rich.console import Console

from app.cli.interactive_menu import _choose_ai
from app.core.settings import Settings


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


def test_menu_selects_route_through_omniroute(monkeypatch):
    _answers(monkeypatch, [1, 2])

    selected = _choose_ai(_console(), _settings())

    assert selected is not None
    assert selected.source == "gateway"
    assert selected.provider == "omniroute"
    assert selected.model == "infra-fast"
    assert selected.label == "OmniRoute → Análise rápida"


def test_menu_accepts_manual_gateway_route_with_only_token(monkeypatch):
    _answers(monkeypatch, [1, "combo/manual"])
    settings = _settings(omniroute_default_route="", omniroute_routes="", omniroute_model="")

    selected = _choose_ai(_console(), settings)

    assert selected is not None
    assert selected.source == "gateway"
    assert selected.model == "combo/manual"


def test_menu_keeps_direct_provider_as_separate_option(monkeypatch):
    _answers(monkeypatch, [2, 1])

    selected = _choose_ai(_console(), _settings())

    assert selected is not None
    assert selected.source == "direct"
    assert selected.provider == "gemini"
    assert selected.model == "gemini-test"


def test_menu_keeps_ollama_as_local_option(monkeypatch):
    _answers(monkeypatch, [3])

    selected = _choose_ai(_console(), _settings())

    assert selected is not None
    assert selected.source == "local"
    assert selected.provider == "ollama"
    assert selected.model == "ollama-test"
