from app.core.policies import EnvironmentType
from app.services.ssh import CommandResult
from app.services.tool_registry import execute_tool, resolve_tool


class FakeExecutor:
    def __init__(self):
        self.commands = []

    def run(self, command, environment, approved=False, timeout=60):
        self.commands.append((command, approved))
        return CommandResult(command, 0, "active\n", "")

    def run_sudo(self, command, environment, approved=False, timeout=60):
        self.commands.append((command, approved))
        return CommandResult(command, 0, "active\n", "")


def test_tool_arguments_reject_shell_injection():
    result = execute_tool(
        FakeExecutor(),
        EnvironmentType.MONITORING,
        "systemd.inspect_unit",
        {"unit": "sshd; reboot"},
    )
    assert result["status"] == "blocked"


def test_correction_is_blocked_in_production_before_execution():
    executor = FakeExecutor()
    result = execute_tool(
        executor,
        EnvironmentType.PRODUCTION,
        "systemd.recover_unit",
        {"unit": "check-mk-agent.socket", "action": "restart"},
        approved=True,
    )
    assert result["status"] == "blocked"
    assert executor.commands == []


def test_correction_requires_approval():
    result = execute_tool(
        FakeExecutor(),
        EnvironmentType.MONITORING,
        "systemd.recover_unit",
        {"unit": "check-mk-agent.socket", "action": "restart"},
        approved=False,
    )
    assert result["status"] == "approval_required"


def test_approved_correction_runs_precondition_and_functional_validation():
    executor = FakeExecutor()
    result = execute_tool(
        executor,
        EnvironmentType.MONITORING,
        "systemd.recover_unit",
        {"unit": "check-mk-agent.socket", "action": "restart"},
        approved=True,
    )
    assert result["status"] == "validated"
    assert result["preconditions"]
    assert len(result["validations"]) >= 2
    assert any(approved for _, approved in executor.commands)


def test_resolved_correction_contains_no_automatic_rollback_when_unsafe():
    plan = resolve_tool(
        "systemd.recover_unit",
        {"unit": "check-mk-agent.socket", "action": "start"},
    )
    assert plan.correction
    assert plan.rollback_command is None
