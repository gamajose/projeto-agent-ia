from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci-release.yml"
DEPLOY_SCRIPT = ROOT / "deploy" / "scripts" / "deploy_release.sh"
RELEASE_UNITS = ROOT / "deploy" / "systemd" / "release"
AUTO_MERGE_WORKFLOW = ROOT / ".github" / "workflows" / "auto-merge.yml"


def test_production_deploy_runs_only_after_main_validation_and_tag() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "ready_for_review" in workflow
    assert "workflow_dispatch:" in workflow
    assert "release_sha:" in workflow
    assert 'O SHA solicitado não é o HEAD atual da main.' in workflow
    assert "needs:\n      - validate\n      - tag" in workflow
    assert "github.event_name == 'workflow_dispatch'" in workflow
    assert "runs-on: [self-hosted, Linux, X64, agent-ia-prod]" in workflow
    assert "bash deploy/scripts/deploy_release.sh --activate" in workflow
    assert "pull_request_target" not in workflow


def test_deploy_requires_exact_sha_and_keeps_secrets_outside_checkout() -> None:
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert 'AGENT_DEPLOY_APPROVED_SHA:-}" == "$RELEASE_SHA"' in script
    assert 'GITHUB_REF:-}" == "refs/heads/main"' in script
    assert 'GITHUB_EVENT_NAME:-}" == "workflow_dispatch"' in script
    assert "--exclude='.env'" in script
    assert "$HOME/.config/agent-ia/production.env" in script
    assert "git reset --hard" not in script


def test_virtualenv_is_created_at_its_final_non_relocated_path() -> None:
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert 'STAGE_DIR="$RELEASE_DIR"' in script
    assert 'mv "$STAGE_DIR" "$RELEASE_DIR"' not in script
    assert 'mktemp -d "$RELEASES_DIR/' not in script


def test_release_units_follow_atomic_current_symlink() -> None:
    for unit_name in ("agent-ia-api.service", "agent-ia-worker@.service"):
        unit = (RELEASE_UNITS / unit_name).read_text(encoding="utf-8")
        assert "agent-ia-production/current" in unit
        assert "EnvironmentFile=%h/.config/agent-ia/production.env" in unit
        assert "projeto-agent-ia/.env" not in unit


def test_auto_merge_uses_workflow_run_payload_for_pull_request() -> None:
    workflow = AUTO_MERGE_WORKFLOW.read_text(encoding="utf-8")

    assert "github.event.workflow_run.pull_requests[0].number" in workflow
    assert 'actions/runs/${RUN_ID}/pull_requests' not in workflow
    assert "actions: write" in workflow
    assert "gh workflow run ci-release.yml" in workflow
    assert 'release_sha="$MERGE_SHA"' in workflow
