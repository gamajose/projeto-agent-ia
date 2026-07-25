from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex

import paramiko

from app.core.policies import EnvironmentType, classify_command, evaluate_action
from app.services.correction_policy import validate_correction


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str


class SSHExecutor:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str | None = None,
        connect_timeout: int = 15,
        *,
        private_key_path: str | None = None,
        private_key_passphrase: str | None = None,
        allow_agent: bool = True,
        look_for_keys: bool = True,
        strict_host_key_checking: bool = True,
        known_hosts_path: str = "~/.ssh/known_hosts",
        bastion_host: str | None = None,
        bastion_port: int = 22,
        bastion_user: str | None = None,
        bastion_password: str | None = None,
        bastion_private_key_path: str | None = None,
        bastion_private_key_passphrase: str | None = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        self.private_key_path = str(Path(private_key_path).expanduser()) if private_key_path else None
        self.private_key_passphrase = private_key_passphrase
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self.strict_host_key_checking = strict_host_key_checking
        self.known_hosts_path = str(Path(known_hosts_path).expanduser())
        self.bastion_host = bastion_host
        self.bastion_port = bastion_port
        self.bastion_user = bastion_user
        self.bastion_password = bastion_password
        self.bastion_private_key_path = str(Path(bastion_private_key_path).expanduser()) if bastion_private_key_path else None
        self.bastion_private_key_passphrase = bastion_private_key_passphrase
        self.client: paramiko.SSHClient | None = None
        self.bastion_client: paramiko.SSHClient | None = None

    def _configure_host_keys(self, client: paramiko.SSHClient) -> None:
        client.load_system_host_keys()
        known_hosts = Path(self.known_hosts_path)
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        if self.strict_host_key_checking:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _common_connect_args(self) -> dict:
        return {
            "timeout": self.connect_timeout,
            "auth_timeout": self.connect_timeout,
            "banner_timeout": self.connect_timeout,
            "allow_agent": self.allow_agent,
            "look_for_keys": self.look_for_keys,
        }

    def connect(self) -> None:
        sock = None
        if self.bastion_host:
            bastion = paramiko.SSHClient()
            self._configure_host_keys(bastion)
            bastion.connect(
                hostname=self.bastion_host,
                port=self.bastion_port,
                username=self.bastion_user or self.username,
                password=self.bastion_password or None,
                key_filename=self.bastion_private_key_path,
                passphrase=self.bastion_private_key_passphrase,
                **self._common_connect_args(),
            )
            transport = bastion.get_transport()
            if transport is None or not transport.is_active():
                bastion.close()
                raise paramiko.SSHException("transporte do bastion não ficou ativo")
            sock = transport.open_channel(
                "direct-tcpip",
                (self.host, self.port),
                ("127.0.0.1", 0),
                timeout=self.connect_timeout,
            )
            self.bastion_client = bastion

        client = paramiko.SSHClient()
        self._configure_host_keys(client)
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password or None,
            key_filename=self.private_key_path,
            passphrase=self.private_key_passphrase,
            sock=sock,
            **self._common_connect_args(),
        )
        self.client = client

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None
        if self.bastion_client:
            self.bastion_client.close()
            self.bastion_client = None

    def _validate(self, command: str, environment: EnvironmentType, approved: bool) -> None:
        action = classify_command(command)
        decision = evaluate_action(action, environment)
        if not decision.allowed:
            raise PermissionError(f"{decision.policy_code}: {decision.reason}")
        if decision.requires_approval and not approved:
            raise PermissionError(f"{decision.policy_code}: aprovação explícita necessária")

        if approved:
            correction = validate_correction(command)
            if not correction.allowed:
                raise PermissionError(f"CORRECTION_POLICY_BLOCKED: {correction.reason}")

    def run(self, command: str, environment: EnvironmentType, approved: bool = False, timeout: int = 60) -> CommandResult:
        if not self.client:
            raise RuntimeError("Conexão SSH não iniciada.")

        self._validate(command, environment, approved)
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(command, exit_code, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"))

    def run_sudo(self, command: str, environment: EnvironmentType, approved: bool = False, timeout: int = 60) -> CommandResult:
        if not self.client:
            raise RuntimeError("Conexão SSH não iniciada.")

        self._validate(command, environment, approved)
        if self.password:
            wrapped = f"sudo -S -p '' sh -lc {shlex.quote(command)}"
            stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=False)
            stdin.write(self.password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
        else:
            wrapped = f"sudo -n sh -lc {shlex.quote(command)}"
            _, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=False)
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(command, exit_code, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"))
