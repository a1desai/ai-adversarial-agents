# =============================================================================
# tests/unit/test_verification_agent.py
# OWNER: Red Team Hire
# MARKERS: unit (no Ollama or Docker — all external calls mocked)
# PURPOSE: Tests for VerificationAgent.verify() and helpers.
# RUN: pytest tests/unit/test_verification_agent.py -v
# =============================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.red_team.verification_agent import VerificationAgent
from agents.shared.mcp_transport import ToolResult

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TARGET_URL = "http://localhost:8080"
_TARGET_CVE = "CVE-2021-42013"

_CLAIMED_OUTCOME = {
    "payload_used": "' OR 1=1--",
    "server_response": "Welcome admin",
    "exploit_claimed_success": True,
}

_GRADER_JSON_SUCCESS = json.dumps(
    {
        "success": True,
        "attack_goals": ["unauthorized_login"],
    }
)

_GRADER_JSON_NO_GOALS = json.dumps(
    {
        "success": True,
    }
)

_GRADER_JSON_FAILURE = json.dumps(
    {
        "success": False,
        "attack_goals": [],
    }
)

_GRADER_UNSTRUCTURED = "Exploit confirmed: unauthorized access to admin panel achieved."

_LLM_RESPONSE = json.dumps(
    {
        "confirmed": True,
        "attack_goals_achieved": ["unauthorized_login"],
        "grader_response": _GRADER_UNSTRUCTURED,
        "confidence": 0.7,
    }
)


def _make_agent():
    with (
        patch("agents.red_team.verification_agent.get_client"),
        patch("agents.red_team.verification_agent.RedTeamTransport"),
    ):
        return VerificationAgent()


def _tool_result(output: str, success: bool = True, error: str | None = None) -> ToolResult:
    return ToolResult(
        tool="curl",
        success=success,
        raw_output=output,
        truncated=False,
        token_estimate=len(output) // 4,
        error=error,
    )


def _mock_usage():
    usage = MagicMock()
    usage.total = 80
    return usage


# ---------------------------------------------------------------------------
# verify — grader JSON parseable (no LLM needed)
# ---------------------------------------------------------------------------


class TestVerifyGraderJson:
    def test_confirmed_true_when_grader_returns_goals(self):
        agent = _make_agent()
        agent.transport.run_tool = MagicMock(return_value=_tool_result(_GRADER_JSON_SUCCESS))

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        assert result["confirmed"] is True
        assert "unauthorized_login" in result["attack_goals_achieved"]
        assert result["confidence"] == 0.9

    def test_confirmed_false_when_grader_returns_empty_goals(self):
        agent = _make_agent()
        agent.transport.run_tool = MagicMock(return_value=_tool_result(_GRADER_JSON_FAILURE))

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        assert result["confirmed"] is False
        assert result["attack_goals_achieved"] == []
        assert result["confidence"] == 0.0

    def test_filters_invalid_goals_from_grader(self):
        agent = _make_agent()
        grader_with_bad_goal = json.dumps(
            {
                "success": True,
                "attack_goals": ["unauthorized_login", "not_a_real_goal"],
            }
        )
        agent.transport.run_tool = MagicMock(return_value=_tool_result(grader_with_bad_goal))

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        assert "unauthorized_login" in result["attack_goals_achieved"]
        assert "not_a_real_goal" not in result["attack_goals_achieved"]

    def test_grader_url_uses_grade_endpoint(self):
        agent = _make_agent()
        mock_run = MagicMock(return_value=_tool_result(_GRADER_JSON_SUCCESS))
        agent.transport.run_tool = mock_run

        agent.verify("http://localhost:8080", _TARGET_CVE, _CLAIMED_OUTCOME)

        _, kwargs = mock_run.call_args
        assert kwargs.get("target") == "http://localhost:8080/grade"

    def test_trailing_slash_stripped_from_url(self):
        agent = _make_agent()
        mock_run = MagicMock(return_value=_tool_result(_GRADER_JSON_SUCCESS))
        agent.transport.run_tool = mock_run

        agent.verify("http://localhost:8080/", _TARGET_CVE, _CLAIMED_OUTCOME)

        _, kwargs = mock_run.call_args
        assert kwargs.get("target") == "http://localhost:8080/grade"


# ---------------------------------------------------------------------------
# verify — grader unreachable
# ---------------------------------------------------------------------------


class TestVerifyGraderUnreachable:
    def test_returns_failed_result_when_transport_fails(self):
        agent = _make_agent()
        agent.transport.run_tool = MagicMock(
            return_value=_tool_result("", success=False, error="Connection refused")
        )

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        assert result["confirmed"] is False
        assert result["confidence"] == 0.0
        assert result["attack_goals_achieved"] == []

    def test_returns_failed_result_when_grader_empty(self):
        agent = _make_agent()
        agent.transport.run_tool = MagicMock(return_value=_tool_result(""))

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        assert result["confirmed"] is False
        assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# verify — unstructured grader response falls back to LLM
# ---------------------------------------------------------------------------


class TestVerifyLlmFallback:
    def test_llm_called_for_unstructured_response(self):
        agent = _make_agent()
        agent.transport.run_tool = MagicMock(return_value=_tool_result(_GRADER_UNSTRUCTURED))
        agent.llm.chat = MagicMock(return_value=(_LLM_RESPONSE, _mock_usage()))

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        agent.llm.chat.assert_called_once()
        assert result["confirmed"] is True
        assert result["confidence"] == 0.7

    def test_llm_non_json_returns_failed_result(self):
        agent = _make_agent()
        agent.transport.run_tool = MagicMock(return_value=_tool_result(_GRADER_UNSTRUCTURED))
        agent.llm.chat = MagicMock(return_value=("I cannot determine this.", _mock_usage()))

        result = agent.verify(_TARGET_URL, _TARGET_CVE, _CLAIMED_OUTCOME)

        assert result["confirmed"] is False
        assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# _parse_grader_goals
# ---------------------------------------------------------------------------


class TestParseGraderGoals:
    def test_extracts_attack_goals_key(self):
        agent = _make_agent()
        result = agent._parse_grader_goals(json.dumps({"attack_goals": ["unauthorized_login"]}))
        assert result == ["unauthorized_login"]

    def test_extracts_goals_key(self):
        agent = _make_agent()
        result = agent._parse_grader_goals(json.dumps({"goals": ["file_access"]}))
        assert result == ["file_access"]

    def test_returns_empty_list_for_success_flag_only(self):
        agent = _make_agent()
        result = agent._parse_grader_goals(json.dumps({"success": True}))
        assert result == []

    def test_returns_none_for_non_json(self):
        agent = _make_agent()
        result = agent._parse_grader_goals("not json at all")
        assert result is None

    def test_filters_unknown_goals(self):
        agent = _make_agent()
        result = agent._parse_grader_goals(
            json.dumps({"attack_goals": ["unauthorized_login", "made_up_goal"]})
        )
        assert result == ["unauthorized_login"]


# ---------------------------------------------------------------------------
# _parse_llm_response
# ---------------------------------------------------------------------------


class TestParseLlmResponse:
    def test_valid_response_parsed(self):
        agent = _make_agent()
        result = agent._parse_llm_response(_LLM_RESPONSE, _GRADER_UNSTRUCTURED)
        assert result["confirmed"] is True
        assert result["attack_goals_achieved"] == ["unauthorized_login"]
        assert result["confidence"] == 0.7

    def test_strips_markdown_fences(self):
        agent = _make_agent()
        fenced = f"```json\n{_LLM_RESPONSE}\n```"
        result = agent._parse_llm_response(fenced, "")
        assert result["confirmed"] is True

    def test_confirmed_true_with_no_valid_goals_set_to_false(self):
        agent = _make_agent()
        bad = json.dumps(
            {
                "confirmed": True,
                "attack_goals_achieved": ["not_valid"],
                "grader_response": "",
                "confidence": 0.8,
            }
        )
        result = agent._parse_llm_response(bad, "")
        assert result["confirmed"] is False
        assert result["confidence"] == 0.0

    def test_missing_key_returns_failed_result(self):
        agent = _make_agent()
        incomplete = json.dumps({"confirmed": True})
        result = agent._parse_llm_response(incomplete, "")
        assert result["confirmed"] is False
        assert result["confidence"] == 0.0
