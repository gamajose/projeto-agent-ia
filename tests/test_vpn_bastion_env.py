from unittest.mock import MagicMock, patch

from app.core.policies import EnvironmentType
from app.core.settings import Settings
from app.services.runner import ResolvedTarget, build_executor


def _settings_from_legacy_vpn_env(monkeypatch) -> Settings:
    monkeypatch.setenv("POSTGRES_DSN", "postgresql+psycopg://agent:secret@127.0.0.1/agent")
    monkeypatch.setenv("SSH_DEFAULT_USER", "2com")
    monkeypatch.setenv("SSH_DEFAULT_PASSWORD", "client-password")
    monkeypatch.setenv("SSH_SRV_VPN_IP", "10.17.181.1")
    monkeypatch.setenv("SSH_SRV_VPN_PORT", "22")
    monkeypatch.setenv("SSH_SRV_VPN_USER", "jose.moraes")
    monkeypatch.setenv("SSH_SRV_VPN_SENHA", "vpn-password")
    return Settings(_env_file=None)


def test_legacy_vpn_environment_names_configure_bastion(monkeypatch):
    settings = _settings_from_legacy_vpn_env(monkeypatch)

    assert settings.ssh_bastion_host == "10.17.181.1"
    assert settings.ssh_bastion_port == 22
    assert settings.ssh_bastion_user == "jose.moraes"
    assert settings.ssh_bastion_password == "vpn-password"


def test_runner_opens_client_connection_through_vpn_server(monkeypatch):
    settings = _settings_from_legacy_vpn_env(monkeypatch)
    target = ResolvedTarget(
        reference="cliente-vpn",
        host="172.27.232.205",
        port=22,
        environment=EnvironmentType.PRODUCTION,
        inventory=None,
    )
    executor = build_executor(target, settings=settings)

    bastion_client = MagicMock()
    target_client = MagicMock()
    transport = MagicMock()
    channel = MagicMock()
    transport.is_active.return_value = True
    transport.open_channel.return_value = channel
    bastion_client.get_transport.return_value = transport

    with patch(
        "app.services.ssh.paramiko.SSHClient",
        side_effect=[bastion_client, target_client],
    ):
        executor.connect()

    assert bastion_client.connect.call_args.kwargs["hostname"] == "10.17.181.1"
    assert bastion_client.connect.call_args.kwargs["username"] == "jose.moraes"
    assert bastion_client.connect.call_args.kwargs["password"] == "vpn-password"
    transport.open_channel.assert_called_once_with(
        "direct-tcpip",
        ("172.27.232.205", 22),
        ("127.0.0.1", 0),
        timeout=settings.ssh_connect_timeout,
    )
    assert target_client.connect.call_args.kwargs["hostname"] == "172.27.232.205"
    assert target_client.connect.call_args.kwargs["username"] == "2com"
    assert target_client.connect.call_args.kwargs["password"] == "client-password"
    assert target_client.connect.call_args.kwargs["sock"] is channel
