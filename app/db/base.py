from __future__ import annotations

from threading import Lock

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.settings import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(settings.postgres_dsn, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

_schema_lock = Lock()
_schema_initialized = False


def ensure_database_schema() -> list[str]:
    """Garante que todas as tabelas ORM existam antes do uso do agente.

    O import dos modelos é intencionalmente tardio para registrar todas as
    tabelas no metadata sem criar dependência circular durante a inicialização.
    ``create_all`` é idempotente: cria apenas tabelas ausentes e não apaga dados.
    Retorna a lista de tabelas criadas nesta chamada.
    """
    global _schema_initialized

    if _schema_initialized:
        return []

    with _schema_lock:
        if _schema_initialized:
            return []

        from app.db import models  # noqa: F401

        inspector = inspect(engine)
        before = set(inspector.get_table_names())
        Base.metadata.create_all(bind=engine, checkfirst=True)
        after = set(inspect(engine).get_table_names())

        _schema_initialized = True
        return sorted(after - before)
