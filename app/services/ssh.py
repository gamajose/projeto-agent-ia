from __future__ import annotations

from dataclasses import dataclass
import shlex

import paramiko

from app.core.policies import EnvironmentType, classify_command, evaluate_action


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str


class SSHExecutor:
    def __init__(self, host: str, port: int, username: str, password: str, connect_timeout: int = 15):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        self.client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.connect_timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        self.client = client

    def close(self) -> None:
        if self.client:
            self.client.close()

    def _validate(self, command: str, environment: EnvironmentType, approved: bool) -> None:
        action = classify_command(command)
        decision = evaluate_action(action, environment)
        if not decision.allowed:
            raise PermissionError(f"{decision.policy_code}: {decision.reason}")
        if decision.requires_approval and not approved:
            raise PermissionError(f"{decision.policy_code}: aprovação explícita necessária")

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
        wrapped = f"sudo -S -p '' sh -lc {shlex.quote(command)}"
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=False)
        stdin.write(self.password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(command, exit_code, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"))
