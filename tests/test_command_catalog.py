from app.services.command_catalog import validate_command


def test_allows_read_only_commands() -> None:
    for command in ("uptime", "free -h", "df -hT", "vmstat 1 5", "systemctl status sshd --no-pager"):
        allowed, _, spec = validate_command(command)
        assert allowed is True
        assert spec is not None


def test_blocks_mutating_commands() -> None:
    for command in ("reboot", "systemctl restart sshd", "rm -rf /tmp/test", "docker restart checkmk"):
        allowed, _, _ = validate_command(command)
        assert allowed is False
