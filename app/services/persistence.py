from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import aliased

from app.db.base import SessionLocal
from app.db.models import HostORM, IncidentORM, InvestigationORM, MonitoringMappingORM


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


def resolve_saved_target(reference: str, environment: str | None = None) -> dict[str, Any] | None:
    value = reference.strip()
    if not value:
        return None
    with SessionLocal() as session:
        monitor_host = aliased(HostORM)
        stmt = (
            select(MonitoringMappingORM, monitor_host)
            .join(monitor_host, monitor_host.id == MonitoringMappingORM.monitoring_host_id)
            .where(or_(
                MonitoringMappingORM.site_name.ilike(value),
                MonitoringMappingORM.container_name.ilike(value),
                MonitoringMappingORM.checkmk_hostname.ilike(value),
            ))
            .order_by(MonitoringMappingORM.last_validated_at.desc())
        )
        row = session.execute(stmt).first()
        if row:
            mapping, host = row
            return {
                "vpn_ip": host.vpn_ip, "ssh_port": host.ssh_port, "host_type": host.host_type,
                "hostname": host.hostname, "environment": host.environment,
                "site_name": mapping.site_name, "container_name": mapping.container_name,
                "source": "monitoring_mapping",
            }
        host_stmt = select(HostORM).where(or_(HostORM.vpn_ip == value, HostORM.hostname.ilike(value)))
        if environment:
            host_stmt = host_stmt.where(HostORM.environment == environment)
        host = session.scalar(host_stmt.order_by(HostORM.last_seen_at.desc()))
        if host:
            return {
                "vpn_ip": host.vpn_ip, "ssh_port": host.ssh_port, "host_type": host.host_type,
                "hostname": host.hostname, "environment": host.environment,
                "site_name": None, "container_name": None, "source": "host",
            }
    return None


def recurrence_history(*, checkmk_host: str, service_name: str, days: int = 30) -> list[dict[str, Any]]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with SessionLocal() as session:
        rows = session.scalars(
            select(IncidentORM)
            .where(IncidentORM.checkmk_host == checkmk_host, IncidentORM.service_name == service_name, IncidentORM.detected_at >= since)
            .order_by(IncidentORM.detected_at.desc()).limit(20)
        ).all()
        return [{
            "id": str(row.id), "state": row.state, "output": row.normalized_output,
            "root_cause_status": row.root_cause_status, "root_cause": row.root_cause,
            "detected_at": row.detected_at.isoformat() if row.detected_at else None,
            "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
            "evidence": row.evidence,
        } for row in rows]


def save_incident(*, affected_host_id, site_name: str | None, checkmk_host: str,
                  service_name: str, state: str, normalized_output: str,
                  evidence: dict[str, Any], analysis: dict[str, Any]) -> str:
    with SessionLocal() as session:
        incident = IncidentORM(
            affected_host_id=affected_host_id, site_name=site_name, checkmk_host=checkmk_host,
            service_name=service_name, state=state, normalized_output=normalized_output,
            root_cause_status=analysis.get("classification", "inconclusive"),
            root_cause=analysis.get("probable_cause"), evidence={"collection": evidence, "analysis": analysis},
        )
        session.add(incident)
        session.commit()
        session.refresh(incident)
        return str(incident.id)


def recent_investigations(*, target: str, hostname: str | None, limit: int = 5) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        conditions = [InvestigationORM.target == target]
        if hostname:
            conditions.append(InvestigationORM.hostname == hostname)
        rows = session.scalars(
            select(InvestigationORM)
            .where(or_(*conditions))
            .order_by(InvestigationORM.created_at.desc())
            .limit(limit)
        ).all()
        return [{
            "id": str(row.id), "objective": row.objective, "status": row.status,
            "confidence": row.confidence, "profile": row.profile,
            "analysis": row.analysis, "created_at": row.created_at.isoformat() if row.created_at else None,
        } for row in rows]


def save_investigation(*, target: str, hostname: str | None, objective: str, environment: str,
                       mode: str, status: str, confidence: int, profile: str | None,
                       model: str | None, duration_ms: int, plans: list, evidence: list,
                       assessments: list, analysis: dict, diagnostics: list) -> str:
    with SessionLocal() as session:
        row = InvestigationORM(
            target=target, hostname=hostname, objective=objective, environment=environment,
            mode=mode, status=status, confidence=confidence, profile=profile, model=model,
            duration_ms=duration_ms, plans=plans, evidence=evidence, assessments=assessments,
            analysis=analysis, diagnostics=diagnostics,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return str(row.id)
