from app.services.playbooks import reload_playbooks, select_playbook
from app.services.tool_registry import describe_tools


def test_expected_operational_playbooks_are_loaded():
    playbooks = reload_playbooks()
    ids = {item.id for item in playbooks}
    assert {
        "checkmk-systemd-socket-summary",
        "checkmk-automation-helper-stopped",
        "checkmk-agent-port-6556",
        "checkmk-rrdcached-stopped",
        "checkmk-container-unhealthy",
        "checkmk-snmp-timeout",
        "checkmk-service-vanished",
        "linux-filesystem-high",
        "linux-swap-high",
        "network-ssh-reset-peer",
        "network-vpn-tunnel-down",
    } <= ids


def test_socket_summary_selects_specific_playbook():
    playbook = select_playbook("Falha no sensor Systemd Socket Summary", "checkmk")
    assert playbook is not None
    assert playbook.id == "checkmk-systemd-socket-summary"
    assert "systemd.recover_unit" in playbook.allowed_corrections


def test_every_playbook_step_uses_registered_tool():
    registered = {item["name"] for item in describe_tools()}
    for playbook in reload_playbooks():
        for step in playbook.steps:
            assert step["tool"] in registered, f"{playbook.id}: {step['tool']}"
        for validation in playbook.validation_tools:
            assert validation["tool"] in registered, f"{playbook.id}: {validation['tool']}"
