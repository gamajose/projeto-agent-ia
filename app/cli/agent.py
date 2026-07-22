from __future__ import annotations

from app.cli.main import app


def main() -> None:
    """Entrypoint do comando único ``agent``."""
    app()


if __name__ == "__main__":
    main()
