from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.core.policies import EnvironmentType


class HostType(StrEnum):
    LINUX = "linux"
    PFSENSE = "pfsense"


class RootCauseStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INCONCLUSIVE = "inconclusive"


class HostTarget(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    host_type: HostType
    vpn_ip: str
    ssh_port: int = 22
    hostname: str | None = None
    internal_ips: list[str] = Field(default_factory=list)
    os_name: str | None = None
    environment: EnvironmentType = EnvironmentType.UNKNOWN
    last_seen_at: datetime | None = None


class MonitoringMapping(BaseModel):
    affected_host_id: UUID
    monitoring_host_id: UUID
    same_server: bool
    container_name: str | None = None
    site_name: str | None = None
    checkmk_hostname: str | None = None
    checkmk_version: str | None = None
    last_validated_at: datetime | None = None


class IncidentFingerprint(BaseModel):
    site_name: str | None = None
    checkmk_host: str
    service_name: str
    state: str
    normalized_output: str | None = None


class IncidentRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    fingerprint: IncidentFingerprint
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None
    root_cause_status: RootCauseStatus = RootCauseStatus.INCONCLUSIVE
    root_cause: str | None = None
    actions: list[dict] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    recurrence_count_7d: int = 0
    recurrence_count_30d: int = 0
