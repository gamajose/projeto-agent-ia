import os
from unittest.mock import patch

from typer.testing import CliRunner

os.environ.setdefault("POSTGRES_DSN", "sqlite+pysqlite:///:memory:")

from app.cli.agent import app
from app.services.codex_cli import CodexCLIStatus
from app.services.provider_preflight import ProviderPreflight, ProviderState


def test_menu_does_not_initialize_database_or_ssh():
    runner = CliRunner()
    row = ProviderPreflight(
        provider="gemini",
        label="Google Gemini",
        state=ProviderState.AVAILABLE,
        model="gemini-test",
        detail="validado",
        selectable=True,
    )
    codex = CodexCLIStatus(False, None, "não identificado", "/tmp")
    with patch("app.cli.agent.ensure_database_schema") as database, patch(
        "app.cli.agent.preflight_all", return_value=[row]
    ), patch("app.cli.agent.codex_cli_status", return_value=codex):
        result = runner.invoke(app, ["--menu"], input="1\n")

    assert result.exit_code == 0
    assert "Google Gemini" in result.stdout
    assert "Nenhuma conexão remota foi iniciada" in result.stdout
    database.assert_not_called()
