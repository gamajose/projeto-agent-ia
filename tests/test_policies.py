from app.core.policies import ActionType, EnvironmentType, classify_command, evaluate_action


def test_reboot_denied_in_all_environments():
    for environment in EnvironmentType:
        assert not evaluate_action(ActionType.HOST_REBOOT, environment).allowed


def test_database_clients_are_blocked():
    assert classify_command("sqlplus / as sysdba") == ActionType.DATABASE_ACCESS
    assert not evaluate_action(ActionType.DATABASE_ACCESS, EnvironmentType.MONITORING).allowed


def test_destructive_commands_are_blocked():
    for command in ("systemctl stop docker", "rm -rf /tmp/teste"):
        action = classify_command(command)
        assert action == ActionType.DESTRUCTIVE
        assert not evaluate_action(action, EnvironmentType.MONITORING).allowed


def test_container_lifecycle_is_always_blocked():
    for command in (
        "docker start checkmk-soc-25",
        "docker stop checkmk-soc-25",
        "docker restart checkmk-soc-25",
        "docker kill checkmk-soc-25",
        "docker rm checkmk-soc-25",
    ):
        action = classify_command(command)
        assert action == ActionType.CONTAINER_ADJUSTMENT
        decision = evaluate_action(action, EnvironmentType.MONITORING)
        assert not decision.allowed
        assert decision.policy_code == "CONTAINER_LIFECYCLE_DENIED"


def test_service_adjustments_require_approval_in_monitoring():
    for command in (
        "systemctl restart check-mk-agent.socket",
        "systemctl stop check-mk-agent.socket && systemctl start check-mk-agent.socket",
    ):
        action = classify_command(command)
        assert action == ActionType.SERVICE_ADJUSTMENT
        decision = evaluate_action(action, EnvironmentType.MONITORING)
        assert decision.allowed
        assert decision.requires_approval


def test_changes_are_blocked_in_unknown_production_and_standby():
    for environment in (EnvironmentType.UNKNOWN, EnvironmentType.PRODUCTION, EnvironmentType.STANDBY):
        decision = evaluate_action(ActionType.SERVICE_ADJUSTMENT, environment)
        assert not decision.allowed
        assert decision.requires_approval


def test_omd_adjustments_are_allowed_only_in_monitoring_or_training():
    for environment in (EnvironmentType.MONITORING, EnvironmentType.TRAINING):
        decision = evaluate_action(ActionType.OMD_ADJUSTMENT, environment)
        assert decision.allowed
        assert decision.requires_approval
