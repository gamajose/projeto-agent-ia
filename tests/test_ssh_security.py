from unittest.mock import MagicMock, patch

import paramiko

from app.services.ssh import SSHExecutor


def test_strict_host_key_checking_uses_reject_policy():
    executor = SSHExecutor("192.0.2.10", 22, "2com", strict_host_key_checking=True)
    with patch("app.services.ssh.paramiko.SSHClient") as ssh_client_class:
        client = ssh_client_class.return_value
        executor.connect()
    policy = client.set_missing_host_key_policy.call_args.args[0]
    assert isinstance(policy, paramiko.RejectPolicy)


def test_non_strict_mode_must_be_explicit():
    executor = SSHExecutor("192.0.2.10", 22, "2com", strict_host_key_checking=False)
    with patch("app.services.ssh.paramiko.SSHClient") as ssh_client_class:
        client = ssh_client_class.return_value
        executor.connect()
    policy = client.set_missing_host_key_policy.call_args.args[0]
    assert isinstance(policy, paramiko.AutoAddPolicy)


def test_bastion_opens_direct_tcp_channel_without_proxy_shell():
    bastion = MagicMock()
    target = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    channel = MagicMock()
    transport.open_channel.return_value = channel
    bastion.get_transport.return_value = transport

    executor = SSHExecutor(
        "10.45.1.24",
        22,
        "opc",
        bastion_host="10.17.181.1",
        bastion_user="jose",
        strict_host_key_checking=True,
    )
    with patch("app.services.ssh.paramiko.SSHClient", side_effect=[bastion, target]):
        executor.connect()

    transport.open_channel.assert_called_once()
    assert target.connect.call_args.kwargs["sock"] is channel
    assert target.connect.call_args.kwargs["hostname"] == "10.45.1.24"
