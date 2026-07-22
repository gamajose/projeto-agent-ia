from app.core.policies import ActionType, EnvironmentType, classify_command, evaluate_action


def test_reboot_denied_in_production():
    decision = evaluate_action(ActionType.HOST_REBOOT, EnvironmentType.PRODUCTION)
    assert not decision.allowed


def test_reboot_requires_approval_in_training():
    decision = evaluate_action(ActionType.HOST_REBOOT, EnvironmentType.TRAINING)
    assert decision.allowed and decision.requires_approval


def test_database_clients_are_blocked():
    assert classify_command("sqlplus / as sysdba") == ActionType.DATABASE_ACCESS
    assert not evaluate_action(ActionType.DATABASE_ACCESS, EnvironmentType.TRAINING).allowed
