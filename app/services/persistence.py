from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.models import HostORM, IncidentORM, MonitoringMappingORM


def upsert_host(*, host_type: str, vpn_ip: str, ssh_port: int, hostname: str, os_name: str,
                environment: str, internal_ips: list[str]) -> HostORM:
    with SessionLocal() as session:
        host = session.scalar(select(HostORM).where(HostORM.vpn_ip == vpn_ip, HostORM.ssh_port == ssh_port))
        if host is None:
            host = HostORM(host_type=host_type, vpn_ip=vpn_ip, ssh_port=ssh_port)
            session.add(host)
        host.hostname = hostname
        host.os_name = os_name
        host.environment = environment
        host.internal_ips = internal_ips
        host.last_seen_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(host)
        session.expunge(host)
        return host


def upsert_mapping(*, affected_host_id, monitoring_host_id, same_server: bool,
                   container_name: str | None, site_name: str | None,
                   checkmk_hostname: str | None, checkmk_version: str | None) -> None:
    with SessionLocal() as session:
        mapping = session.scalar(select(MonitoringMappingORM).where(
            MonitoringMappingORM.affected_host_id == affected_host_id
        ))
        if mapping is None:
            mapping = MonitoringMappingORM(
                affected_host_id=affected_host_id,
                monitoring_host_id=monitoring_host_id,
                same_server=same_server,
            )
            session.add(mapping)
        mapping.monitoring_host_id = monitoring_host_id
        mapping.same_server = same_server
        mapping.container_name = container_name
        mapping.site_name = site_name
        mapping.checkmk_hostname = checkmk_hostname
        mapping.checkmk_version = checkmk_version
        mapping.last_validated_at = datetime.now(timezone.utc)
        session.commit()


def recurrence_history(*, checkmk_host: str, service_name: str, days: int = 30) -> list[dict[str, Any]]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with SessionLocal() as session:
        rows = session.scalars(
            select(IncidentORM)
            .where(
                IncidentORM.checkmk_host == checkmk_host,
                IncidentORM.service_name == service_name,
                IncidentORM.detected_at >= since,
            )
            .order_by(IncidentORM.detected_at.desc())
            .limit(20)
        ).all()
        return [
            {
                "id": str(row.id),
                "state": row.state,
                "output": row.normalized_output,
                "root_cause_status": row.root_cause_status,
                "root_cause": row.root_cause,
                "detected_at": row.detected_at.isoformat() if row.detected_at else None,
                "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
                "evidence": row.evidence,
            }
            for row in rows
        ]


def save_incident(*, affected_host_id, site_name: str | None, checkmk_host: str,
                  service_name: str, state: str, normalized_output: str,
                  evidence: dict[str, Any], analysis: dict[str, Any]) -> str:
    with SessionLocal() as session:
        incident = IncidentORM(
            affected_host_id=affected_host_id,
            site_name=site_name,
            checkmk_host=checkmk_host,
            service_name=service_name,
            state=state,
            normalized_output=normalized_output,
            root_cause_status=analysis.get("classification", "inconclusive"),
            root_cause=analysis.get("probable_cause"),
            evidence={"collection": evidence, "analysis": analysis},
        )
        session.add(incident)
        session.commit()
        session.refresh(incident)
        return str(incident.id)
