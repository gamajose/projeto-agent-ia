from __future__ import annotations

import os
import re
import socket
import threading
from pathlib import Path

import paramiko
import yaml


HOST = os.getenv("LAB_HOST", "0.0.0.0")
PORT = int(os.getenv("LAB_PORT", "2222"))
USERNAME = os.getenv("LAB_USER", "lab")
PASSWORD = os.getenv("LAB_PASSWORD", "lab")
SCENARIO_FILE = Path(os.getenv("LAB_SCENARIO", "/labs/scenarios/checkmk-systemd-socket.yml"))


def load_scenario() -> dict:
    return yaml.safe_load(SCENARIO_FILE.read_text(encoding="utf-8")) or {}


def resolve_response(command: str, scenario: dict) -> tuple[int, str, str]:
    for item in scenario.get("responses") or []:
        pattern = str(item.get("pattern") or "")
        if pattern and re.search(pattern, command, flags=re.IGNORECASE | re.DOTALL):
            return int(item.get("exit_code") or 0), str(item.get("stdout") or ""), str(item.get("stderr") or "")
    default = scenario.get("default") or {}
    return int(default.get("exit_code") or 0), str(default.get("stdout") or ""), str(default.get("stderr") or "")


class LabServer(paramiko.ServerInterface):
    def __init__(self, scenario: dict):
        self.scenario = scenario

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str):
        return paramiko.AUTH_SUCCESSFUL if username == USERNAME and password == PASSWORD else paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command: bytes):
        text = command.decode(errors="replace")

        def respond() -> None:
            code, stdout, stderr = resolve_response(text, self.scenario)
            if stdout:
                channel.send(stdout.encode())
            if stderr:
                channel.send_stderr(stderr.encode())
            channel.send_exit_status(code)
            channel.close()

        threading.Thread(target=respond, daemon=True).start()
        return True


def handle_client(client: socket.socket, host_key: paramiko.PKey, scenario: dict) -> None:
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    try:
        transport.start_server(server=LabServer(scenario))
        while transport.is_active():
            transport.accept(timeout=1)
    finally:
        transport.close()
        client.close()


def main() -> None:
    scenario = load_scenario()
    host_key = paramiko.RSAKey.generate(2048)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)
    print(f"Lab SSH ouvindo em {HOST}:{PORT}; cenário={SCENARIO_FILE}", flush=True)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client, host_key, scenario), daemon=True).start()


if __name__ == "__main__":
    main()
