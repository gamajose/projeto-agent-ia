from __future__ import annotations

import json
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from redis import Redis

from app.core.policies import EnvironmentType
from app.core.settings import Settings, get_settings
from app.services.redaction import redact_object
from app.services.runner import run_target


class JobError(RuntimeError):
    pass


def _redis(settings: Settings) -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True)


def _result_key(settings: Settings, job_id: str) -> str:
    return f"{settings.agent_result_prefix}{job_id}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store(client: Redis, settings: Settings, job_id: str, payload: dict[str, Any]) -> None:
    client.setex(
        _result_key(settings, job_id),
        max(60, int(settings.agent_job_ttl_seconds)),
        json.dumps(redact_object(payload), ensure_ascii=False, default=str),
    )


def enqueue_investigation(
    reference: str,
    objective: str,
    *,
    environment: EnvironmentType = EnvironmentType.UNKNOWN,
    mode: str = "propose",
    approve: bool = False,
    ssh_port: int | None = None,
    metadata: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    if mode == "correct" and approve:
        # O webhook distribuído nunca transforma fila em autorização implícita.
        approve = False
        mode = "propose"
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "reference": reference,
        "objective": objective,
        "environment": environment.value,
        "mode": mode,
        "approve": approve,
        "ssh_port": ssh_port,
        "metadata": redact_object(metadata or {}),
        "created_at": _now(),
    }
    client = _redis(settings)
    _store(client, settings, job_id, {"job_id": job_id, "status": "queued", "created_at": job["created_at"]})
    client.rpush(settings.agent_queue_name, json.dumps(job, ensure_ascii=False, default=str))
    return {
        "job_id": job_id,
        "status": "queued",
        "queue": settings.agent_queue_name,
        "worker_pool": settings.agent_worker_name,
    }


def get_job(job_id: str, *, settings: Settings | None = None) -> dict[str, Any] | None:
    settings = settings or get_settings()
    value = _redis(settings).get(_result_key(settings, job_id))
    if not value:
        return None
    payload = json.loads(value)
    return payload if isinstance(payload, dict) else None


def _execute_job(job: dict[str, Any], *, settings: Settings) -> dict[str, Any]:
    job_id = str(job["job_id"])
    client = _redis(settings)
    worker = f"{settings.agent_worker_name}@{socket.gethostname()}"
    _store(
        client,
        settings,
        job_id,
        {
            "job_id": job_id,
            "status": "running",
            "worker": worker,
            "started_at": _now(),
        },
    )
    try:
        environment = EnvironmentType(job.get("environment") or EnvironmentType.UNKNOWN.value)
        result = run_target(
            str(job["reference"]),
            str(job.get("objective") or ""),
            environment=environment,
            mode=str(job.get("mode") or "propose"),
            approve=bool(job.get("approve", False)),
            ssh_port=job.get("ssh_port"),
            settings=settings,
        )
        payload = {
            "job_id": job_id,
            "status": "completed",
            "worker": worker,
            "completed_at": _now(),
            "investigation_id": result.get("investigation_id"),
            "result": result,
        }
        _store(client, settings, job_id, payload)
        return payload
    except Exception as exc:
        payload = {
            "job_id": job_id,
            "status": "failed",
            "worker": worker,
            "completed_at": _now(),
            "error": f"{type(exc).__name__}: {exc}",
        }
        _store(client, settings, job_id, payload)
        return payload


def run_worker_once(
    *,
    settings: Settings | None = None,
    block_seconds: int | None = None,
) -> dict[str, Any] | None:
    settings = settings or get_settings()
    timeout = settings.agent_queue_block_seconds if block_seconds is None else block_seconds
    item = _redis(settings).blpop(settings.agent_queue_name, timeout=max(0, int(timeout)))
    if not item:
        return None
    _, raw = item
    try:
        job = json.loads(raw)
        if not isinstance(job, dict) or not job.get("job_id"):
            raise JobError("job inválido")
    except Exception as exc:
        raise JobError(f"não foi possível decodificar o job: {exc}") from exc
    return _execute_job(job, settings=settings)


def worker_loop(*, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    while True:
        try:
            run_worker_once(settings=settings)
        except KeyboardInterrupt:
            return
        except Exception:
            time.sleep(2)
