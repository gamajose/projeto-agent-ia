from app.services.redaction import redact_object, redact_text


def test_redacts_api_keys_passwords_and_database_urls():
    text = "API_KEY=abc123 password=secret postgresql://user:pass@db/agent"
    result = redact_text(text)
    assert "abc123" not in result
    assert "secret" not in result
    assert ":pass@" not in result


def test_redacts_snmp_community_from_command():
    result = redact_text("snmpwalk -v2c -c fwdoiscom 192.0.2.1 .1.3.6")
    assert "fwdoiscom" not in result
    assert "[REDACTED]" in result


def test_redacts_sensitive_dictionary_keys_recursively():
    result = redact_object({"token": "abc", "nested": {"password": "secret", "safe": "ok"}})
    assert result["token"] == "[REDACTED]"
    assert result["nested"]["password"] == "[REDACTED]"
    assert result["nested"]["safe"] == "ok"
