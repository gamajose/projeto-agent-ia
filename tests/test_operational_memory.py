from pathlib import Path

import pytest

from app.core.settings import get_settings
from app.services.operational_memory import _case_score, build_operational_memory
from app.services.playbooks import load_playbooks, playbook_summary, reload_playbooks, select_playbook


@pytest.fixture(autouse=True)
def clear_caches():
    get_settings.cache_clear()
    load_playbooks.cache_clear()
    yield
    get_settings.cache_clear()
    load_playbooks.cache_clear()


def _configure_playbooks(monkeypatch):
    monkeypatch.setenv("POSTGRES_DSN", "postgresql+psycopg://agent:agent@127.0.0.1/agent")
    monkeypatch.setenv(
        "AGENT_PLAYBOOK_DIR",
        str(Path(__file__).resolve().parents[1] / "config" / "playbooks"),
    )
    get_settings.cache_clear()
    reload_playbooks()


def test_verified_case_records_playbook_cause_and_successful_tools():
    memory = build_operational_memory(
        objective="SNMP da iDRAC sem resposta",
        profile="checkmk",
        playbook_id="checkmk-snmp-timeout",
        analysis={
            "status": "healthy",
            "confidence": 91,
            "probable_cause": "IP antigo configurado no Checkmk",
            "conclusion": "O endereço foi comparado e a coleta está normalizada.",
        },
        evidence=[
            {
                "tool": "checkmk.diagnose_snmp_address",
                "status": "executed",
                "exit_code": 0,
            }
        ],
        corrections=[],
        target="172.27.232.109",
        hostname="2com-monitor",
    )

    assert memory["validation_state"] == "verified"
    assert memory["category"] == "monitoring"
    assert memory["component"] == "idrac"
    assert memory["playbook_id"] == "checkmk-snmp-timeout"
    assert memory["successful_tools"] == ["checkmk.diagnose_snmp_address"]


def test_case_score_prioritizes_same_component_profile_and_playbook():
    memory = {
        "symptom": "Falha SNMP na iDRAC",
        "probable_cause": "IP antigo no Checkmk",
        "resolution_summary": "Endereço corrigido",
        "tags": ["snmp", "idrac", "checkmk"],
        "category": "monitoring",
        "component": "idrac",
        "profile": "checkmk",
        "playbook_id": "checkmk-snmp-timeout",
        "target": "monitor-a",
        "validation_state": "verified",
        "confidence": 90,
    }

    same = _case_score(
        objective="Comunicação SNMP da iDRAC sem resposta",
        profile="checkmk",
        playbook_id="checkmk-snmp-timeout",
        target="monitor-a",
        memory=memory,
    )
    different = _case_score(
        objective="Filesystem raiz acima de 90 por cento",
        profile="linux_generic",
        playbook_id="linux-filesystem-high",
        target="monitor-b",
        memory=memory,
    )

    assert same > different
    assert same >= 0.45


def test_select_playbook_can_reuse_verified_database_case(monkeypatch):
    _configure_playbooks(monkeypatch)
    monkeypatch.setattr(
        "app.services.playbooks.recommended_playbook_id",
        lambda objective, profile: "checkmk-snmp-timeout",
    )
    monkeypatch.setattr(
        "app.services.playbooks.playbook_effectiveness_bonus",
        lambda playbook_id, profile: 0,
    )

    selected = select_playbook("evento zeta sem padrão textual cadastrado", "linux_generic")

    assert selected is not None
    assert selected.id == "checkmk-snmp-timeout"


def test_playbook_summary_exposes_database_learning(monkeypatch):
    _configure_playbooks(monkeypatch)
    monkeypatch.setattr(
        "app.services.playbooks.playbook_learning_summary",
        lambda playbook_id, profile: {
            "playbook_id": playbook_id,
            "runs": 8,
            "conclusive_runs": 7,
            "verified_runs": 4,
            "conclusive_rate": 0.875,
            "common_causes": [{"cause": "IP alterado", "count": 3}],
            "successful_tools": [{"tool": "checkmk.diagnose_snmp_address", "count": 4}],
        },
    )
    selected = select_playbook("SNMP sem resposta na iDRAC", "checkmk")
    summary = playbook_summary(selected)

    assert summary is not None
    assert summary["database_learning"]["runs"] == 8
    assert summary["database_learning"]["common_causes"][0]["cause"] == "IP alterado"
