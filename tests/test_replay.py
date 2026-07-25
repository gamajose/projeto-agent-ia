from types import SimpleNamespace
from unittest.mock import patch

from app.services.replay import replay_investigation


class FakeProvider:
    name = "gemini"
    model = "gemini-test"

    def generate_json(self, prompt):
        assert "Não há acesso ao servidor" in prompt
        return ({"status": "attention", "confidence": 88, "summary": "reanalisado", "facts": [], "probable_cause": "socket inativo", "conclusion": "causa confirmada", "recommendations": [], "evidence_map": [], "ticket_report": "relatório"}, {"response_chars": 10})


def test_replay_uses_only_persisted_evidence():
    investigation = {
        "id": "id",
        "objective": "socket falhou",
        "target": "monitor",
        "hostname": "monitor",
        "environment": "monitoring",
        "profile": "checkmk",
        "plans": [],
        "evidence": [{"tool": "systemd.inspect_unit", "stdout": "inactive"}],
        "assessments": [],
        "analysis": {"status": "attention"},
    }
    with patch("app.services.replay.get_investigation", return_value=investigation), patch("app.services.replay.get_provider", return_value=FakeProvider()):
        result = replay_investigation("id", settings=SimpleNamespace())
    assert result["remote_connection_started"] is False
    assert result["analysis"]["probable_cause"] == "socket inativo"
