from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services.secrets import SecretBackendError, clear_secret_cache, get_secret, secret_backend_status


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"data": {"data": {"GEMINI_API_KEY": "vault-gemini", "SSH_DEFAULT_PASSWORD": "vault-ssh"}}}


def vault_settings(**overrides):
    values = {
        "secret_backend": "vault",
        "vault_addr": "https://vault.invalid",
        "vault_token": "vault-token",
        "vault_namespace": None,
        "vault_kv_mount": "secret",
        "vault_secret_path": "agent-ia",
        "vault_verify_tls": True,
        "vault_cache_seconds": 60,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_env_backend_uses_fallback_without_network():
    settings = SimpleNamespace(secret_backend="env")
    with patch("app.services.secrets.httpx.get") as request:
        assert get_secret("GEMINI_API_KEY", "local-key", settings=settings) == "local-key"
    request.assert_not_called()


def test_vault_kv_v2_has_precedence_and_uses_tls_verification():
    clear_secret_cache()
    with patch("app.services.secrets.httpx.get", return_value=FakeResponse()) as request:
        value = get_secret("GEMINI_API_KEY", "fallback", settings=vault_settings())
    assert value == "vault-gemini"
    kwargs = request.call_args.kwargs
    assert kwargs["verify"] is True
    assert kwargs["headers"]["X-Vault-Token"] == "vault-token"
    assert request.call_args.args[0].endswith("/v1/secret/data/agent-ia")


def test_vault_status_never_contains_token_value():
    status = secret_backend_status(vault_settings())
    assert status["backend"] == "vault"
    assert status["vault_token_configured"] is True
    assert "vault-token" not in repr(status)


def test_unknown_backend_is_rejected():
    with pytest.raises(SecretBackendError, match="desconhecido"):
        get_secret("X", settings=SimpleNamespace(secret_backend="arquivo"))
