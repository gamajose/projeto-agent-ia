from __future__ import annotations

import sys

from rich.console import Console

from app.cli.help_screen import (
    render_full_help,
    render_version,
    should_show_full_help,
    should_show_version,
)


console = Console()


def _run_menu() -> None:
    """Carrega dependências operacionais apenas quando o menu for solicitado."""
    from app.cli.agent import _prepare_database, _show_result
    from app.cli.interactive_menu import run_main_menu
    from app.core.settings import get_settings

    run_main_menu(
        console=console,
        show_result=_show_result,
        prepare_database=_prepare_database,
        settings=get_settings(),
    )


def _run_legacy_cli() -> None:
    """Carrega o CLI operacional somente para comandos que realmente precisam dele."""
    from app.cli.agent import main as legacy_main

    legacy_main()


def main() -> None:
    """Intercepta ajuda e versão antes de carregar banco, SSH e runtime operacional."""
    args = sys.argv[1:]

    if should_show_full_help(args):
        render_full_help(console)
        return

    if should_show_version(args):
        render_version(console)
        return

    if "--menu" in args:
        _run_menu()
        return

    _run_legacy_cli()


if __name__ == "__main__":
    main()
