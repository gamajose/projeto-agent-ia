from __future__ import annotations

from io import StringIO
from unittest.mock import Mock, patch

import pytest
import typer
from rich.console import Console

from app.cli.interactive_menu import _choose_number
from app.cli.menu_control import (
    EXIT_COMMANDS,
    MenuExitRequested,
    global_menu_exit,
    is_exit_command,
)


@pytest.mark.parametrize("command", sorted(EXIT_COMMANDS))
def test_recognizes_global_exit_commands(command: str):
    assert is_exit_command(command)
    assert is_exit_command(f"  {command.upper()}  ")


def test_does_not_treat_normal_input_as_exit():
    assert not is_exit_command("1")
    assert not is_exit_command("continuar")
    assert not is_exit_command(None)


def test_numeric_prompt_preserves_valid_integer_conversion():
    original_prompt = Mock(return_value="2")

    with patch("app.cli.menu_control.typer.prompt", original_prompt):
        with global_menu_exit():
            assert typer.prompt("Opção", type=int) == 2

    original_prompt.assert_called_once()


def test_numeric_prompt_preserves_invalid_input_validation():
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None)
    original_prompt = Mock(side_effect=["d", "2"])

    with patch("app.cli.menu_control.typer.prompt", original_prompt):
        with global_menu_exit():
            result = _choose_number(console, "Ambiente", minimum=1, maximum=5)

    assert result == 2
    assert "Informe um número válido" in output.getvalue()


@pytest.mark.parametrize("command", ["q", "\\q", "quit", "exit", "sair", "encerrar", "fechar", "esc"])
def test_exit_command_interrupts_any_prompt(command: str):
    original_prompt = Mock(return_value=command)

    with patch("app.cli.menu_control.typer.prompt", original_prompt):
        with global_menu_exit():
            with pytest.raises(MenuExitRequested):
                typer.prompt("Ambiente", type=int)


@pytest.mark.parametrize("error", [EOFError(), KeyboardInterrupt(), typer.Abort()])
def test_terminal_interruptions_request_clean_exit(error: BaseException):
    original_prompt = Mock(side_effect=error)

    with patch("app.cli.menu_control.typer.prompt", original_prompt):
        with global_menu_exit():
            with pytest.raises(MenuExitRequested):
                typer.prompt("Servidor")


def test_original_typer_prompt_is_restored_after_context():
    original_prompt = typer.prompt

    with global_menu_exit():
        assert typer.prompt is not original_prompt

    assert typer.prompt is original_prompt
