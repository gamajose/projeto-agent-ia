from app.services.correction_policy import validate_correction
from app.services.operation_intent import infer_operation_intent


def test_portuguese_validation_words_force_read_only() -> None:
    for text in (
        "valide o Checkmk",
        "pode verificar o problema no Checkmk?",
        "analise a memória do servidor",
        "investigue o automation-helper",
        "diagnosticar lentidão",
    ):
        intent = infer_operation_intent(text)
        assert intent.mode == "investigate"
        assert intent.approve is False
        assert intent.read_only is True


def test_problem_without_validation_verb_runs_safe_correction_mode() -> None:
    intent = infer_operation_intent("problema no Checkmk, automation-helper parado")
    assert intent.mode == "correct"
    assert intent.approve is True
    assert intent.read_only is False


def test_safe_monitoring_recovery_is_allowed() -> None:
    assert validate_correction("systemctl restart check-mk-agent.socket").allowed
    assert validate_correction("systemctl enable --now check-mk-agent.socket").allowed
    assert validate_correction("omd restart automation-helper").allowed
    assert validate_correction("docker exec checkmk-abc su - abc -c 'omd restart automation-helper'").allowed


def test_dangerous_or_protected_actions_are_blocked() -> None:
    commands = (
        "reboot",
        "shutdown -h now",
        "rm -rf /tmp/teste",
        "systemctl stop check-mk-agent.socket",
        "systemctl restart postgresql",
        "systemctl restart docker",
        "docker restart checkmk-abc",
        "docker stop checkmk-abc",
        "dnf update -y",
        "firewall-cmd --add-port=6556/tcp",
        "omd restart mysql",
    )
    for command in commands:
        assert not validate_correction(command).allowed, command
