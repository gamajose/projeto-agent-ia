from app.core.policies import ActionType, EnvironmentType, classify_command, evaluate_action


def test_reboot_denied_in_production():
    decision = evaluate_action(ActionType.HOST_REBOOT, EnvironmentType.PRODUCTION)
    assert not decision.allowed


def test_reboot_denied_in_standby():
    decision = evaluate_action(ActionType.HOST_REBOOT, EnvironmentType.STANDBY)
    assert not decision.allowed


def test_reboot_denied_in_monitoring():
    decision = evaluate_action(ActionType.HOST_REBOOT, EnvironmentType.MONITORING)
    assert not decision.allowed


def test_database_clients_are_blocked():
    assert classify_command("sqlplus / as sysdba") == ActionType.DATABASE_ACCESS
    assert not evaluate_action(ActionType.DATABASE_ACCESS, EnvironmentType.MONITORING).allowed
