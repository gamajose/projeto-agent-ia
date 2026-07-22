from app.core.policies import ActionType, EnvironmentType, classify_command, evaluate_action


def test_reboot_denied_in_all_environments():
    for environment in (EnvironmentType.PRODUCTION, EnvironmentType.STANDBY, EnvironmentType.MONITORING):
        assert not evaluate_action(ActionType.HOST_REBOOT, environment).allowed


def test_database_clients_are_blocked():
    assert classify_command("sqlplus / as sysdba") == ActionType.DATABASE_ACCESS
    assert not evaluate_action(ActionType.DATABASE_ACCESS, EnvironmentType.MONITORING).allowed


def test_destructive_commands_are_blocked():
    for command in ("systemctl stop docker", "docker rm checkmk", "rm -rf /tmp/teste"):
        action = classify_command(command)
        assert action == ActionType.DESTRUCTIVE
        assert not evaluate_action(action, EnvironmentType.MONITORING).allowed


def test_safe_adjustments_are_allowed():
    for command in ("systemctl restart check-mk-agent.socket", "docker restart checkmk-soc-25"):
        action = classify_command(command)
        decision = evaluate_action(action, EnvironmentType.MONITORING)
        assert decision.allowed
        assert not decision.requires_approval
