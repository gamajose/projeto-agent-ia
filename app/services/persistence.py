from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import aliased

from app.db.base import SessionLocal
from app.db.models import ApprovalExecutionORM, HostORM, IncidentORM, InvestigationORM, MonitoringMappingORM
from app.services.operational_memory import build_operational_memory, search_operational_cases


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
            .where(InvestigationORM.checkmk_host == checkmk_host, InvestigationORM.service_name == service_name, InvestigationORM.detected_at >= since)
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


def _investigation_dict(row: InvestigationORM, *, include_evidence: bool = False) -> dict[str, Any]:
    result = {
        "id": str(row.id), "target": row.target, "hostname": row.hostname,
        "objective": row.objective, "environment": row.environment, "mode": row.mode,
        "status": row.status, "confidence": row.confidence, "profile": row.profile,
        "model": row.model, "duration_ms": row.duration_ms, "analysis": row.analysis,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if include_evidence:
        result.update({
            "plans": row.plans, "evidence": row.evidence,
            "assessments": row.assessments, "diagnostics": row.diagnostics,
        })
    return result


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
        return [_investigation_dict(row) for row in rows]


def similar_investigations(*, objective: str, profile: str | None, target: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
    """Recupera somente casos úteis ou verificados da memória operacional."""
    cases = search_operational_cases(
        objective=objective,
        profile=profile,
        playbook_id=None,
        target=target,
        limit=limit,
    )
    for case in cases:
        case.setdefault("status", case.get("outcome_status"))
        case.setdefault("objective", case.get("symptom"))
        case.setdefault("analysis", {"probable_cause": case.get("probable_cause")})
    return cases


def get_investigation(investigation_id: str, *, include_evidence: bool = True) -> dict[str, Any] | None:
    try:
        identifier = uuid.UUID(str(investigation_id))
    except ValueError:
        return None
    with SessionLocal() as session:
        row = session.get(InvestigationORM, identifier)
        return _investigation_dict(row, include_evidence=include_evidence) if row else None


def update_investigation_analysis(investigation_id: str, analysis: dict[str, Any]) -> bool:
    try:
        identifier = uuid.UUID(str(investigation_id))
    except ValueError:
        return False
    with SessionLocal() as session:
        row = session.get(InvestigationORM, identifier)
        if not row:
            return False
        row.analysis = analysis
        session.commit()
        return True


def _playbook_id_from_plans(plans: list[dict[str, Any]]) -> str | None:
    for plan in plans:
        playbook = plan.get("playbook") or {}
        if isinstance(playbook, dict) and playbook.get("id"):
            return str(playbook["id"])
    return None


def save_investigation(*, target: str, hostname: str | None, objective: str, environment: str,
                       mode: str, status: str, confidence: int, profile: str | None,
                       model: str | None, duration_ms: int, plans: list, evidence: list,
                       assessments: list, analysis: dict, diagnostics: list) -> str:
    analysis_payload = dict(analysis or {})
    analysis_payload["operational_memory"] = build_operational_memory(
        objective=objective,
        profile=profile,
        playbook_id=_playbook_id_from_plans(plans),
        analysis=analysis_payload,
        evidence=evidence,
        corrections=list(analysis_payload.get("corrections") or []),
        target=target,
        hostname=hostname,
    )

    with SessionLocal() as session:
        row = InvestigationORM(
            target=target, hostname=hostname, objective=objective, environment=environment,
            mode=mode, status=status, confidence=confidence, profile=profile, model=model,
            duration_ms=duration_ms, plans=plans, evidence=evidence, assessments=assessments,
            analysis=analysis_payload, diagnostics=diagnostics,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return str(row.id)


def create_approval_execution(*, investigation_id: str, token_digest: str, requested_by: str | None, actions: list[dict[str, Any]]) -> str:
    with SessionLocal() as session:
        row = ApprovalExecutionORM(
            investigation_id=uuid.UUID(investigation_id), token_digest=token_digest,
            requested_by=requested_by, status="pending", actions=actions, results=[],
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return str(row.id)


def complete_approval_execution(execution_id: str, *, status: str, results: list[dict[str, Any]]) -> None:
    with SessionLocal() as session:
        row = session.get(ApprovalExecutionORM, uuid.UUID(execution_id))
        if not row:
            return
        row.status = status
        row.results = results
        row.executed_at = datetime.now(timezone.utc)
        session.commit()


def operational_metrics() -> dict[str, Any]:
    with SessionLocal() as session:
        total = int(session.scalar(select(func.count(InvestigationORM.id))) or 0)
        average_duration = float(session.scalar(select(func.avg(InvestigationORM.duration_ms))) or 0)
        status_rows = session.execute(select(InvestigationORM.status, func.count(InvestigationORM.id)).group_by(InvestigationORM.status)).all()
        mode_rows = session.execute(select(InvestigationORM.mode, func.count(InvestigationORM.id)).group_by(InvestigationORM.mode)).all()
        approval_rows = session.execute(select(ApprovalExecutionORM.status, func.count(ApprovalExecutionORM.id)).group_by(ApprovalExecutionORM.status)).all()
        return {
            "investigations_total": total,
            "average_duration_ms": round(average_duration, 2),
            "by_status": {status: int(count) for status, count in status_rows},
            "by_mode": {mode: int(count) for mode, count in mode_rows},
            "approval_executions": {status: int(count) for status, count in approval_rows},
        }
