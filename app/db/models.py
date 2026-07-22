from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class HostORM(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("vpn_ip", "ssh_port", name="uq_host_vpn_port"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_type: Mapped[str] = mapped_column(String(20), nullable=False)
    vpn_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    ssh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    hostname: Mapped[str | None] = mapped_column(String(255))
    internal_ips: Mapped[list] = mapped_column(JSONB, default=list)
    os_name: Mapped[str | None] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class MonitoringMappingORM(Base):
    __tablename__ = "monitoring_mappings"
    __table_args__ = (UniqueConstraint("affected_host_id", name="uq_mapping_affected_host"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    affected_host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    monitoring_host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    same_server: Mapped[bool] = mapped_column(Boolean, nullable=False)
    container_name: Mapped[str | None] = mapped_column(String(255))
    site_name: Mapped[str | None] = mapped_column(String(255))
    checkmk_hostname: Mapped[str | None] = mapped_column(String(255))
    checkmk_version: Mapped[str | None] = mapped_column(String(100))
    last_validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentORM(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    affected_host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    site_name: Mapped[str | None] = mapped_column(String(255))
    checkmk_host: Mapped[str] = mapped_column(String(255), nullable=False)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    normalized_output: Mapped[str | None] = mapped_column(Text)
    root_cause_status: Mapped[str] = mapped_column(String(30), nullable=False, default="inconclusive")
    root_cause: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentActionORM(Base):
    __tablename__ = "incident_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    action_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    policy_code: Mapped[str] = mapped_column(String(80), nullable=False)
    approved_by_user: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    output_excerpt: Mapped[str | None] = mapped_column(Text)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
