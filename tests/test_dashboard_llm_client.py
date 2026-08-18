import pytest

from dashboard._llm_client import NoApiKeyError, ask


def test_ask_raises_no_api_key_error_when_env_var_unset(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(NoApiKeyError):
        ask("system prompt", "user message")
