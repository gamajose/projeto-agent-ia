import os
from unittest.mock import patch

from typer.testing import CliRunner

os.environ.setdefault("POSTGRES_DSN", "sqlite+pysqlite:///:memory:")

from app.cli.agent import app
from app.services.codex_cli import CodexCLIStatus
from app.services.provider_preflight import ProviderPreflight, ProviderState


def test_menu_launches_codex_without_database_or_ssh():
    runner = CliRunner()
    provider_rows = [
        ProviderPreflight(
            provider="gemini",
            label="Google Gemini",
            state=ProviderState.AVAILABLE,
            model="gemini-test",
            detail="validado",
            selectable=True,
        )
    ]
    codex = CodexCLIStatus(
        available=True,
        command="/home/jose/ia/codex/codex",
        version="codex-cli 1.2.3",
        workdir="/home/jose/ia/codex",
    )

    with patch("app.cli.agent.preflight_all", return_value=provider_rows), patch(
        "app.cli.agent.codex_cli_status", return_value=codex
    ), patch("app.cli.agent.launch_codex", return_value=0) as launcher, patch(
        "app.cli.agent.ensure_database_schema"
    ) as database:
        result = runner.invoke(app, ["--menu"], input="2\n")

    assert result.exit_code == 0
    assert "OpenAI Codex CLI" in result.stdout
    assert "/home/jose/ia/codex" in result.stdout
    assert "Nenhuma conexão SSH foi iniciada" in result.stdout
    launcher.assert_called_once()
    database.assert_not_called()
