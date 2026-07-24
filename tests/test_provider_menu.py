import os
from unittest.mock import patch

from typer.testing import CliRunner

os.environ.setdefault("POSTGRES_DSN", "sqlite+pysqlite:///:memory:")

from app.cli.agent import app


def test_menu_does_not_initialize_database_or_ssh():
    runner = CliRunner()
    with patch("app.cli.agent.ensure_database_schema") as database:
        result = runner.invoke(app, ["--menu"], input="1\n")

    assert result.exit_code == 0
    assert "Google Gemini" in result.stdout
    assert "Nenhuma conexão remota foi iniciada" in result.stdout
    database.assert_not_called()
