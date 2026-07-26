from types import SimpleNamespace

from app.core.policies import EnvironmentType
from app.services.interactive_session import OperationalSession


def _result(target: str, objective: str):
    return {
        "investigation_id": "inv-1",
        "hostname": target,
        "target": target,
        "environment_classification": {"environment": "monitoring"},
        "profile": "checkmk",
        "playbook": {"id": "pb", "title": "PB"},
        "analysis": {
            "status": "attention",
            "confidence": 90,
            "summary": f"analisado: {objective}",
            "probable_cause": "serviço parado",
            "proposed_actions": [],
        },
        "evidence": [],
    }


def test_session_preserves_context_and_switches_target(monkeypatch):
    calls = []

    def fake_run_target(reference, objective, **kwargs):
        calls.append((reference, objective, kwargs))
        return _result(reference, objective)

    monkeypatch.setattr("app.services.interactive_session.run_target", fake_run_target)
    session = OperationalSession(
        target="10.0.0.1",
        provider_name="ollama",
        environment=EnvironmentType.UNKNOWN,
        ssh_port=2222,
        settings=SimpleNamespace(),
    )

    session.start("validar socket")
    assert calls[-1][2]["ssh_port"] == 2222
    assert session.environment == EnvironmentType.MONITORING
    session.investigate_more("veja os logs")
    assert "CONTEXTO DA SESSÃO" in calls[-1][1]
    assert "serviço parado" in calls[-1][1]

    session.switch_target("10.0.0.2", ssh_port=2200)
    assert session.target == "10.0.0.2"
    assert session.ssh_port == 2200
    assert session.last_result is None
    assert any(turn.get("kind") == "switch_target" for turn in session.turns)


def test_session_exit_keeps_history():
    session = OperationalSession(
        target="10.0.0.1",
        provider_name="ollama",
        settings=SimpleNamespace(),
    )
    session.close()
    assert session.active is False
    assert session.turns[-1]["kind"] == "exit"
