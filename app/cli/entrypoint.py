from __future__ import annotations

import sys

from app.cli.agent import _prepare_database, _show_result, console, main as legacy_main
from app.cli.interactive_menu import run_main_menu
from app.core.settings import get_settings


def main() -> None:
    """Mantém o CLI atual e intercepta somente o novo menu operacional."""
    if "--menu" in sys.argv[1:]:
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
