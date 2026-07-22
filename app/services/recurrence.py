from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import IncidentORM


def recurrence_summary(db: Session, affected_host_id, service_name: str, site_name: str | None) -> dict:
    now = datetime.now(timezone.utc)

    def count_since(days: int) -> int:
        stmt = select(func.count()).select_from(IncidentORM).where(
            IncidentORM.affected_host_id == affected_host_id,
            IncidentORM.service_name == service_name,
            IncidentORM.detected_at >= now - timedelta(days=days),
        )
        if site_name is None:
            stmt = stmt.where(IncidentORM.site_name.is_(None))
        else:
            stmt = stmt.where(IncidentORM.site_name == site_name)
        return int(db.scalar(stmt) or 0)

    return {"count_7d": count_since(7), "count_30d": count_since(30)}
