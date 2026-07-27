from pathlib import Path

import pytest

from app.core.settings import get_settings
from app.services.playbooks import load_playbooks, reload_playbooks, render_steps, select_playbook
from app.services.tool_registry import resolve_tool


@pytest.fixture(autouse=True)
def clear_settings_and_playbook_caches():
    get_settings.cache_clear()
    load_playbooks.cache_clear()
    yield
    get_settings.cache_clear()
    load_playbooks.cache_clear()


def _load_snmp_playbook(monkeypatch, objective: str):
    monkeypatch.setenv("POSTGRES_DSN", "postgresql+psycopg://agent:agent@127.0.0.1/agent")
    monkeypatch.setenv(
        "AGENT_PLAYBOOK_DIR",
        str(Path(__file__).resolve().parents[1] / "config" / "playbooks"),
    )
    get_settings.cache_clear()
    reload_playbooks()
    return select_playbook(objective, "oracle_linux")


def test_snmp_objective_selects_checkmk_playbook_and_renders_device_ip(monkeypatch):
    objective = (
        "Problema na comunicação snmp com a idrac do srv standby, "
        "ip da idrac 192.168.1.252"
    )

    playbook = _load_snmp_playbook(monkeypatch, objective)

    assert playbook is not None
    assert playbook.id == "checkmk-snmp-timeout"

    steps = render_steps(
        playbook,
        {"target": "172.27.232.109", "hostname": "2com-monitor"},
    )
    tools = [step["tool"] for step in steps]

    assert tools[:2] == ["checkmk.discover", "network.interfaces"]
    assert "network.inspect_route" in tools
    assert "network.udp_probe" in tools
    assert "checkmk.diagnose_snmp_address" in tools

    diagnose = next(step for step in steps if step["tool"] == "checkmk.diagnose_snmp_address")
    assert diagnose["arguments"]["address"] == "192.168.1.252"


def test_snmp_playbook_skips_ip_dependent_steps_when_objective_has_no_ip(monkeypatch):
    playbook = _load_snmp_playbook(monkeypatch, "SNMP sem resposta no host monitorado")

    assert playbook is not None
    steps = render_steps(
        playbook,
        {"target": "monitor", "hostname": "2com-monitor"},
    )
    tools = [step["tool"] for step in steps]

    assert tools == ["checkmk.discover", "network.interfaces"]


def test_checkmk_snmp_address_tool_enters_container_and_omd_site():
    plan = resolve_tool(
        "checkmk.diagnose_snmp_address",
        {"address": "192.168.1.252"},
    )

    assert plan.sudo is True
    assert plan.correction is False
    assert plan.timeout == 300
    assert "docker ps" in plan.command
    assert "omd sites --bare" in plan.command
    assert 'su - "$s" -c' in plan.command
    assert "cmk -l" in plan.command
    assert "cmk -D" in plan.command
    assert "cmk -vvn" in plan.command
    assert "192.168.1.252" in plan.command
