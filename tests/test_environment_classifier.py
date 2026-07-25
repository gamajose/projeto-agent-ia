from app.core.policies import EnvironmentType
from app.services.environment_classifier import classify_environment


def test_explicit_monitoring_environment_is_trusted_for_changes():
    result = classify_environment(requested=EnvironmentType.MONITORING)
    assert result.environment == EnvironmentType.MONITORING
    assert result.source == "operator"
    assert result.confidence == 100
    assert result.trusted_for_changes


def test_inventory_environment_is_trusted():
    result = classify_environment(inventory_environment="training")
    assert result.environment == EnvironmentType.TRAINING
    assert result.source == "inventory"
    assert result.trusted_for_changes


def test_heuristic_environment_never_authorizes_changes():
    result = classify_environment(hostname="checkmk-monitor-01", objective="sensor vermelho")
    assert result.environment == EnvironmentType.MONITORING
    assert result.source == "heuristic"
    assert result.confidence < 90
    assert not result.trusted_for_changes


def test_production_is_never_trusted_for_automatic_changes():
    result = classify_environment(requested=EnvironmentType.PRODUCTION)
    assert result.confidence == 100
    assert not result.trusted_for_changes


def test_unknown_remains_read_only():
    result = classify_environment(hostname="srv01", objective="lentidão")
    assert result.environment == EnvironmentType.UNKNOWN
    assert result.confidence == 0
    assert not result.trusted_for_changes
