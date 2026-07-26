from types import SimpleNamespace

import pytest
from rich.console import Console

from app.cli.interactive_menu import _choose_ssh_port
from app.core.policies import EnvironmentType
from app.services import playbooks
from app.services.approvals import create_approval_token, verify_approval_token
from app.services.runner import resolve_target


def _settings(default_port: int = 22) -> SimpleNamespace:
    return SimpleNamespace(ssh_default_port=default_port)


def _saved_target(port: int = 22) -> dict:
    return {
        "vpn_ip": "192.0.2.10",
        "ssh_port": port,
        "environment": "monitoring",
        "source": "host",
    }


def test_explicit_port_overrides_playbook_and_saved_inventory(monkeypatch):
    monkeypatch.setattr(
        "app.services.runner.resolve_saved_target",
        lambda reference, environment: _saved_target(2022),
    )

    target = resolve_target(
        "srv-noc",
        ssh_port=2222,
        playbook_ssh_port=2200,
        settings=_settings(),
    )

    assert target.host == "192.0.2.10"
    assert target.port == 2222
    assert target.environment == EnvironmentType.MONITORING


def test_playbook_port_overrides_saved_inventory(monkeypatch):
    monkeypatch.setattr(
        "app.services.runner.resolve_saved_target",
        lambda reference, environment: _saved_target(2022),
    )

    target = resolve_target(
        "srv-noc",
        playbook_ssh_port=2200,
        settings=_settings(),
    )

    assert target.port == 2200


def test_saved_inventory_and_default_port_are_fallbacks(monkeypatch):
    monkeypatch.setattr(
        "app.services.runner.resolve_saved_target",
        lambda reference, environment: _saved_target(2022),
    )
    assert resolve_target("srv-noc", settings=_settings()).port == 2022

    monkeypatch.setattr(
        "app.services.runner.resolve_saved_target",
        lambda reference, environment: None,
    )
    assert resolve_target("192.0.2.20", settings=_settings()).port == 22


@pytest.mark.parametrize("port", [0, 65536, "invalida"])
def test_invalid_explicit_port_is_rejected(monkeypatch, port):
    monkeypatch.setattr(
        "app.services.runner.resolve_saved_target",
        lambda reference, environment: None,
    )
    with pytest.raises(ValueError, match="porta SSH informada"):
        resolve_target("192.0.2.20", ssh_port=port, settings=_settings())


def test_playbook_reads_top_level_ssh_port(tmp_path, monkeypatch):
    path = tmp_path / "custom.yml"
    path.write_text(
        """
id: custom
title: Servidor customizado
ssh_port: 2222
profiles: [any]
match:
  any: [custom]
steps: []
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(playbooks, "_playbook_dir", lambda: tmp_path)
    playbooks.load_playbooks.cache_clear()
    try:
        loaded = playbooks.load_playbooks()
        assert loaded[0].ssh_port == 2222
        with playbooks.use_playbook("manual", "custom"):
            assert playbooks.selected_playbook_ssh_port("qualquer objetivo") == (2222, "custom")
    finally:
        playbooks.load_playbooks.cache_clear()


def test_playbook_reads_port_env_before_default_port(tmp_path, monkeypatch):
    path = tmp_path / "inventory.yml"
    path.write_text(
        """
id: inventory
target:
  port_env: CUSTOM_SSH_PORT
  default_port: 22
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("CUSTOM_SSH_PORT", "2201")
    monkeypatch.setattr(playbooks, "_playbook_dir", lambda: tmp_path)
    playbooks.load_playbooks.cache_clear()
    try:
        assert playbooks.load_playbooks()[0].ssh_port == 2201
    finally:
        playbooks.load_playbooks.cache_clear()


def test_menu_accepts_blank_for_playbook_port(monkeypatch):
    monkeypatch.setattr(
        "app.cli.interactive_menu.selected_playbook_ssh_port",
        lambda objective: (2222, "srv-custom"),
    )
    monkeypatch.setattr("app.cli.interactive_menu.typer.prompt", lambda *args, **kwargs: "")

    port, summary = _choose_ssh_port(
        Console(),
        settings=_settings(),
        playbook_mode="auto",
        playbook_id=None,
        objective="validar",
    )

    assert port is None
    assert summary == "2222 (playbook srv-custom)"


def test_menu_validates_and_accepts_explicit_port(monkeypatch):
    answers = iter(["0", "65536", "porta", "2222"])
    monkeypatch.setattr(
        "app.cli.interactive_menu.selected_playbook_ssh_port",
        lambda objective: (None, None),
    )
    monkeypatch.setattr(
        "app.cli.interactive_menu.typer.prompt",
        lambda *args, **kwargs: next(answers),
    )

    port, summary = _choose_ssh_port(
        Console(),
        settings=_settings(),
        playbook_mode="none",
        playbook_id=None,
        objective="validar",
    )

    assert port == 2222
    assert summary == "2222 (informada pelo operador)"


def test_approval_token_preserves_non_default_ssh_port():
    settings = SimpleNamespace(
        approval_secret="test-secret-with-enough-entropy",
        approval_ttl_minutes=30,
    )
    actions = [{"tool": "systemd.recover_unit", "arguments": {}, "status": "proposed"}]

    token = create_approval_token(
        "11111111-1111-1111-1111-111111111111",
        "192.0.2.10",
        actions,
        ssh_port=2222,
        settings=settings,
    )

    assert token
    assert verify_approval_token(token, actions, settings=settings)["ssh_port"] == 2222
