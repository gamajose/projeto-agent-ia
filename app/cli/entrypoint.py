from __future__ import annotations

import sys

from app.cli.agent import _prepare_database, _show_result, console, main as legacy_main
from app.cli.help_screen import (
    render_full_help,
    render_version,
    should_show_full_help,
    should_show_version,
)
from app.cli.interactive_menu import run_main_menu
from app.core.settings import get_settings


def main() -> None:
    """Preserva o CLI atual e intercepta somente recursos globais do aplicativo."""
    args = sys.argv[1:]

    if should_show_full_help(args):
        render_full_help(console)
        return

    if should_show_version(args):
        render_version(console)
        return

    if "--menu" in args:
        run_main_menu(
            console=console,
            show_result=_show_result,
            prepare_database=_prepare_database,
            settings=get_settings(),
        )
        return

    legacy_main()


if __name__ == "__main__":
    main()
