from types import SimpleNamespace
from unittest.mock import patch

from app.services.reviewer import review_corrections


class FakeProvider:
    name = "reviewer"
    model = "reviewer-test"

    def generate_json(self, prompt):
        assert "Não proponha comandos novos" in prompt
        return (
            {
                "approved": True,
                "confidence": 92,
                "agrees_with_probable_cause": True,
                "evidence_supported": True,
                "reason": "evidências e ação estão alinhadas",
                "risks": [],
                "action_reviews": [{"tool": "systemd.recover_unit", "approved": True, "reason": "baixo impacto"}],
            },
            {"response_chars": 100},
        )


def settings():
    return SimpleNamespace(
        ai_reviewer_provider="omniroute",
        ai_reviewer_model="auto/fast",
        ai_reviewer_min_confidence=80,
    )


def test_reviewer_must_agree_with_cause_and_evidence():
    with patch("app.services.reviewer.get_provider", return_value=FakeProvider()) as provider_factory:
        result = review_corrections(
            {"probable_cause": "socket inativo", "status": "critical"},
            [{"tool": "systemd.recover_unit", "arguments": {"unit": "check-mk-agent.socket"}}],
            [{"tool": "systemd.inspect_unit", "stdout": "ActiveState=inactive", "exit_code": 0}],
            settings=settings(),
        )
    provider_factory.assert_called_once_with("omniroute", settings(), "auto/fast")
    assert result["approved"] is True
    assert result["status"] == "approved"
    assert result["confidence"] == 92


def test_no_proposal_does_not_require_reviewer():
    result = review_corrections({}, [], [], settings=settings())
    assert result["status"] == "not_required"
    assert result["approved"] is False
