import json
from types import SimpleNamespace
from unittest.mock import patch

from app.core.policies import EnvironmentType
from app.services.jobs import enqueue_investigation, get_job, run_worker_once


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.queue = []

    def setex(self, key, ttl, value):
        self.values[key] = value

    def get(self, key):
        return self.values.get(key)

    def rpush(self, key, value):
        self.queue.append((key, value))

    def blpop(self, key, timeout=0):
        if not self.queue:
            return None
        queue_key, value = self.queue.pop(0)
        return queue_key, value


def settings():
    return SimpleNamespace(
        redis_url="redis://invalid/1",
        agent_queue_name="agent-ia:jobs",
        agent_result_prefix="agent-ia:result:",
        agent_worker_name="vpn-test",
        agent_job_ttl_seconds=3600,
        agent_queue_block_seconds=0,
    )


def test_enqueue_never_turns_distributed_job_into_implicit_correction():
    fake = FakeRedis()
    config = settings()
    with patch("app.services.jobs._redis", return_value=fake):
        queued = enqueue_investigation(
            "192.0.2.10",
            "corrija o serviço",
            environment=EnvironmentType.MONITORING,
            mode="correct",
            approve=True,
            settings=config,
        )
        stored_status = get_job(queued["job_id"], settings=config)
    assert queued["status"] == "queued"
    job = json.loads(fake.queue[0][1])
    assert job["mode"] == "propose"
    assert job["approve"] is False
    assert stored_status["status"] == "queued"


def test_worker_executes_job_and_persists_redacted_result():
    fake = FakeRedis()
    config = settings()
    with patch("app.services.jobs._redis", return_value=fake):
        queued = enqueue_investigation("192.0.2.10", "validar socket", settings=config)
        with patch("app.services.jobs.run_target", return_value={"investigation_id": "investigation-1", "analysis": {"status": "attention"}}):
            result = run_worker_once(settings=config, block_seconds=0)
        stored = json.loads(fake.values[f"agent-ia:result:{queued['job_id']}"])
    assert result["status"] == "completed"
    assert stored["investigation_id"] == "investigation-1"
    assert stored["worker"].startswith("vpn-test@")


def test_worker_returns_none_when_queue_is_empty():
    with patch("app.services.jobs._redis", return_value=FakeRedis()):
        assert run_worker_once(settings=settings(), block_seconds=0) is None
