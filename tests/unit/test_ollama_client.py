# =============================================================================
# tests/unit/test_ollama_client.py
# OWNER: Lead / any hire
# MARKERS: unit (Ollama is mocked — no GPU required)
# PURPOSE: Tests for agents/shared/ollama_client.py
# RUN: pytest tests/unit/test_ollama_client.py -v
# =============================================================================

from unittest.mock import MagicMock, patch

from agents.shared.ollama_client import (
    TEMPERATURE_MAP,
    TOKEN_BUDGET_PER_ENGAGEMENT,
    ModelRole,
    OllamaClient,
    TaskType,
    TokenUsage,
)

# ---------------------------------------------------------------------------
# Temperature Configuration
# ---------------------------------------------------------------------------


class TestTemperatureConfig:
    def test_patch_generation_has_lowest_temperature(self):
        """Patch generation must be most deterministic — lowest temp."""
        assert TEMPERATURE_MAP[TaskType.PATCH_GENERATION] <= 0.2

    def test_attack_planning_has_highest_temperature(self):
        """Attack planning needs creative lateral thinking — highest temp."""
        assert TEMPERATURE_MAP[TaskType.ATTACK_PLANNING] >= 0.5

    def test_all_task_types_have_temperature(self):
        for task in TaskType:
            assert task in TEMPERATURE_MAP, f"Missing temperature for {task}"

    def test_all_temperatures_in_valid_range(self):
        for task, temp in TEMPERATURE_MAP.items():
            assert 0.0 <= temp <= 1.0, f"Temperature {temp} out of range for {task}"


# ---------------------------------------------------------------------------
# Token Budget Tracking
# ---------------------------------------------------------------------------


class TestTokenUsage:
    def test_total_is_sum_of_prompt_and_completion(self):
        usage = TokenUsage(prompt_tokens=100, completion_tokens=50)
        assert usage.total == 150

    def test_addition_of_two_usages(self):
        a = TokenUsage(100, 50)
        b = TokenUsage(200, 75)
        c = a + b
        assert c.prompt_tokens == 300
        assert c.completion_tokens == 125
        assert c.total == 425

    def test_zero_usage(self):
        usage = TokenUsage()
        assert usage.total == 0


# ---------------------------------------------------------------------------
# OllamaClient (mocked)
# ---------------------------------------------------------------------------


class TestOllamaClient:
    def test_verify_models_returns_true_when_all_present(self, mock_ollama_client):
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock_ollama_client):
            client = OllamaClient()
            assert client.verify_models_available() is True

    def test_verify_models_returns_false_when_missing(self):
        mock = MagicMock()
        mock.list.return_value = MagicMock(models=[])
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock):
            client = OllamaClient()
            assert client.verify_models_available() is False

    def _make_chat_response(
        self, content: str, prompt_tokens: int, completion_tokens: int
    ) -> MagicMock:
        resp = MagicMock()
        resp.message.content = content
        resp.prompt_eval_count = prompt_tokens
        resp.eval_count = completion_tokens
        return resp

    def test_chat_returns_string_and_token_usage(self, mock_ollama_client):
        mock_ollama_client.chat.return_value = self._make_chat_response("test response", 80, 40)
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock_ollama_client):
            client = OllamaClient()
            response, usage = client.chat(
                role=ModelRole.REASONING,
                task=TaskType.LOG_ANALYSIS,
                messages=[{"role": "user", "content": "test"}],
            )
            assert response == "test response"
            assert usage.total == 120

    def test_cumulative_usage_accumulates(self, mock_ollama_client):
        mock_ollama_client.chat.return_value = self._make_chat_response("ok", 100, 50)
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock_ollama_client):
            client = OllamaClient()
            client.chat(
                ModelRole.REASONING, TaskType.LOG_ANALYSIS, [{"role": "user", "content": "a"}]
            )
            client.chat(
                ModelRole.REASONING, TaskType.LOG_ANALYSIS, [{"role": "user", "content": "b"}]
            )
            assert client.cumulative_usage.total == 300

    def test_reset_usage_clears_counter(self, mock_ollama_client):
        mock_ollama_client.chat.return_value = self._make_chat_response("ok", 100, 50)
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock_ollama_client):
            client = OllamaClient()
            client.chat(
                ModelRole.REASONING, TaskType.LOG_ANALYSIS, [{"role": "user", "content": "a"}]
            )
            client.reset_usage()
            assert client.cumulative_usage.total == 0

    def test_is_over_budget_when_exceeded(self, mock_ollama_client):
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock_ollama_client):
            client = OllamaClient()
            # Manually set cumulative usage over budget
            from agents.shared.ollama_client import TokenUsage

            client._cumulative_usage = TokenUsage(TOKEN_BUDGET_PER_ENGAGEMENT, 0)
            assert client.is_over_budget() is True

    def test_system_prompt_prepended_to_messages(self, mock_ollama_client):
        with patch("agents.shared.ollama_client.ollama.Client", return_value=mock_ollama_client):
            client = OllamaClient()
            client.chat(
                role=ModelRole.REASONING,
                task=TaskType.LOG_ANALYSIS,
                messages=[{"role": "user", "content": "hello"}],
                system_prompt="You are a security analyst.",
            )
            call_args = mock_ollama_client.chat.call_args
            messages_sent = call_args[1]["messages"]
            assert messages_sent[0]["role"] == "system"
            assert messages_sent[0]["content"] == "You are a security analyst."
