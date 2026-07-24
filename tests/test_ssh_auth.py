from unittest.mock import patch

from app.services.ssh import SSHExecutor


def test_connect_uses_public_key_and_ssh_agent_configuration() -> None:
    executor = SSHExecutor(
        host="192.0.2.10",
        port=22,
        username="2com",
        password=None,
        private_key_path="~/.ssh/id_ed25519",
        private_key_passphrase="key-secret",
        allow_agent=True,
        look_for_keys=True,
    )

    with patch("app.services.ssh.paramiko.SSHClient") as ssh_client_class:
        client = ssh_client_class.return_value
        executor.connect()

    connect_args = client.connect.call_args.kwargs
    assert connect_args["hostname"] == "192.0.2.10"
    assert connect_args["username"] == "2com"
    assert connect_args["password"] is None
    assert connect_args["key_filename"].endswith("/.ssh/id_ed25519")
    assert connect_args["passphrase"] == "key-secret"
    assert connect_args["allow_agent"] is True
    assert connect_args["look_for_keys"] is True
    assert executor.client is client


def test_connect_can_force_password_authentication() -> None:
    executor = SSHExecutor(
        host="192.0.2.20",
        port=2222,
        username="2com",
        password="secret",
        allow_agent=False,
        look_for_keys=False,
    )

    with patch("app.services.ssh.paramiko.SSHClient") as ssh_client_class:
        client = ssh_client_class.return_value
        executor.connect()

    connect_args = client.connect.call_args.kwargs
    assert connect_args["port"] == 2222
    assert connect_args["password"] == "secret"
    assert connect_args["key_filename"] is None
    assert connect_args["allow_agent"] is False
    assert connect_args["look_for_keys"] is False
