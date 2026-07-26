from types import SimpleNamespace

import pytest

from app.services.approvals import ApprovalError, create_approval_token, verify_approval_token


def settings():
    return SimpleNamespace(approval_secret="test-secret-with-enough-entropy", approval_ttl_minutes=30)


def test_approval_token_is_bound_to_investigation_and_actions():
    actions = [{"tool": "systemd.recover_unit", "arguments": {"unit": "check-mk-agent.socket", "action": "start"}, "status": "proposed"}]
    token = create_approval_token(
        "11111111-1111-1111-1111-111111111111",
        "monitor",
        actions,
        ssh_port=2222,
        settings=settings(),
    )
    assert token
    payload = verify_approval_token(token, actions, settings=settings())
    assert payload["investigation_id"] == "11111111-1111-1111-1111-111111111111"
    assert payload["ssh_port"] == 2222


def test_changed_actions_invalidate_approval():
    actions = [{"tool": "systemd.recover_unit", "arguments": {"unit": "check-mk-agent.socket", "action": "start"}}]
    token = create_approval_token("11111111-1111-1111-1111-111111111111", "monitor", actions, settings=settings())
    changed = [{"tool": "systemd.recover_unit", "arguments": {"unit": "check-mk-agent.socket", "action": "restart"}}]
    with pytest.raises(ApprovalError, match="alteradas"):
        verify_approval_token(token, changed, settings=settings())


def test_tampered_signature_is_rejected():
    actions = [{"tool": "systemd.recover_unit", "arguments": {"unit": "check-mk-agent.socket", "action": "start"}}]
    token = create_approval_token("11111111-1111-1111-1111-111111111111", "monitor", actions, settings=settings())
    with pytest.raises(ApprovalError):
        verify_approval_token(token[:-1] + ("A" if token[-1] != "A" else "B"), actions, settings=settings())
