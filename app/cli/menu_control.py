from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import typer


EXIT_COMMANDS = frozenset(
    {
        "q",
        "\\q",
        "quit",
        "exit",
        "sair",
        "encerrar",
        "fechar",
        "esc",
    }
)


class MenuExitRequested(Exception):
    """Solicita o encerramento limpo do menu interativo."""


def is_exit_command(value: Any) -> bool:
    """Retorna verdadeiro quando a entrada representa um comando global de saída."""

    return isinstance(value, str) and value.strip().casefold() in EXIT_COMMANDS


@contextmanager
def global_menu_exit() -> Iterator[None]:
    """Adiciona saída global aos prompts do Typer durante a execução do menu.

    Os menus numéricos existentes usam ``typer.prompt(..., type=int)``. Para
    reconhecer comandos como ``q`` e ``exit`` antes da conversão, o wrapper lê
    temporariamente esses campos como texto e converte para inteiro em seguida.
    Entradas inválidas continuam gerando ``ValueError`` para que cada menu exiba
    sua mensagem de validação atual.
    """

    original_prompt = typer.prompt

    def prompt_with_global_exit(text: str, *args: Any, **kwargs: Any) -> Any:
        requested_type = kwargs.get("type")
        prompt_kwargs = dict(kwargs)

        if requested_type is int:
            prompt_kwargs["type"] = str

        try:
            value = original_prompt(text, *args, **prompt_kwargs)
        except (EOFError, KeyboardInterrupt, typer.Abort) as exc:
            raise MenuExitRequested() from exc

        if is_exit_command(value):
            raise MenuExitRequested()

        if requested_type is int:
            try:
                return int(str(value).strip())
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{value!r} não é um número inteiro válido") from exc

        return value

    typer.prompt = prompt_with_global_exit
    try:
        yield
    finally:
        typer.prompt = original_prompt
