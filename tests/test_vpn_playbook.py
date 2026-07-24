from pathlib import Path

import yaml


def test_vpn_playbook_is_declarative_and_safe():
    playbook = yaml.safe_load(Path("config/playbooks/vpn-access.yml").read_text(encoding="utf-8"))
    assert playbook["target"]["default_host"] == "10.17.181.1"
    assert playbook["safety"] == {
        "connect_automatically": False,
        "execute_remote_commands": False,
        "access_localhost": False,
        "print_secrets": False,
    }
    assert "password" not in playbook["target"]
