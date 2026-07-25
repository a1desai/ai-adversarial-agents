# =============================================================================
# tests/unit/test_patch_validation_agent.py
# OWNER: Blue Team Hire
# MARKERS: unit (no Ollama or Docker required — all external calls mocked)
# PURPOSE: Tests for PatchValidationAgent.validate() and helpers.
# RUN: pytest tests/unit/test_patch_validation_agent.py -v
# =============================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.blue_team.patch_validation_agent import PatchValidationAgent
from agents.shared.mcp_transport import ToolResult
from evaluation.trace_logger import TraceEvent

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_CONTAINER_ID = "blue-target-1"
_PATCH_DIFF = "--- a/f.php\n+++ b/f.php\n@@ -1 +1 @@\n-old\n+new\n"
_ALLOWED_PATHS = ["vulnerabilities/sqli/source/low.php"]
_HEALTH_URL = "http://localhost:8080/health"
_TRACE_ID = "test-trace-id"


def _make_agent():
    with (
        patch("agents.blue_team.patch_validation_agent.get_client"),
        patch("agents.blue_team.patch_validation_agent.BlueTeamTransport"),
    ):
        return PatchValidationAgent()


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
    usage.total = 70
    return usage


def _exploit_event(payload_used: str, success_indicators: list[str]) -> TraceEvent:
    return TraceEvent(
        trace_id=_TRACE_ID,
        timestamp="2026-07-25T00:00:00+00:00",
        team="red",
        agent="exploitation_agent",
        action="execute_payload",
        input={"target_endpoint": "/vulnerabilities/sqli/"},
        output={
            "payload_used": payload_used,
            "server_response": "Welcome admin",
            "success_indicators": success_indicators,
            "outcome": "SUCCESS",
            "confidence": 0.9,
        },
        tokens_used=0,
        step_number=2,
    )


_PAYLOAD_USED = (
    "curl -s -G --data-urlencode id=1_OR_1=1 http://localhost:8080/vulnerabilities/sqli/"
)
_SUCCESS_INDICATORS = ["First name", "Surname"]

# Real SQLi payloads routinely contain unbalanced quotes shlex can't tokenize.
_UNBALANCED_QUOTE_PAYLOAD = "curl -s -G --data-urlencode id=1' OR 1=1-- http://localhost:8080/x"


# ---------------------------------------------------------------------------
# validate — scope violation short-circuits
# ---------------------------------------------------------------------------


class TestScopeViolation:
    def test_deploy_failure_returns_immediately(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(
            return_value=_tool_result("", success=False, error="Patch scope violation: foo.php")
        )
        agent.transport.run_tool = MagicMock()

        result = agent.validate(_CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID)

        assert result["patch_applies_cleanly"] is False
        assert result["functional_tests_passed"] is False
        assert result["exploit_blocked"] is False
        assert "scope violation" in result["details"].lower()
        agent.transport.run_tool.assert_not_called()


# ---------------------------------------------------------------------------
# validate — deterministic replay (success indicators still match)
# ---------------------------------------------------------------------------


class TestDeterministicReplayStillVulnerable:
    def test_matching_indicators_means_not_blocked_no_llm_call(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[
                _tool_result("200"),  # health check
                _tool_result("First name: admin\nSurname: user"),  # replay — still vulnerable
            ]
        )
        agent.llm.chat = MagicMock()

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_PAYLOAD_USED, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is False
        assert result["regression_introduced"] is False
        agent.llm.chat.assert_not_called()


# ---------------------------------------------------------------------------
# validate — ambiguous replay defers to the LLM rubric
# ---------------------------------------------------------------------------


class TestAmbiguousReplayUsesLlm:
    def test_no_indicators_matched_calls_llm_and_uses_its_verdict(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[
                _tool_result("200"),  # health check
                _tool_result("400 Bad Request: invalid input"),  # replay — clean rejection
            ]
        )
        llm_verdict = {
            "exploit_blocked": True,
            "regression_introduced": False,
            "details": "Replay returned HTTP 400 validation error; no success indicators present.",
        }
        agent.llm.chat = MagicMock(return_value=(json.dumps(llm_verdict), _mock_usage()))

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_PAYLOAD_USED, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is True
        assert result["functional_tests_passed"] is True
        agent.llm.chat.assert_called_once()

    def test_llm_non_json_response_defaults_to_not_blocked(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[_tool_result("200"), _tool_result("something ambiguous")]
        )
        agent.llm.chat = MagicMock(return_value=("not json", _mock_usage()))

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_PAYLOAD_USED, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is False


# ---------------------------------------------------------------------------
# validate — functional health check
# ---------------------------------------------------------------------------


class TestFunctionalHealthCheck:
    def test_5xx_status_is_unhealthy(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[
                _tool_result("500"),
                _tool_result("connection reset"),
            ]
        )
        agent.llm.chat = MagicMock(
            return_value=(
                json.dumps(
                    {"exploit_blocked": False, "regression_introduced": True, "details": "crash"}
                ),
                _mock_usage(),
            )
        )

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_PAYLOAD_USED, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["functional_tests_passed"] is False

    def test_no_response_is_unhealthy(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[
                _tool_result("", success=False, error="timed out"),
                _tool_result(""),
            ]
        )
        agent.llm.chat = MagicMock(
            return_value=(
                json.dumps(
                    {"exploit_blocked": False, "regression_introduced": False, "details": "n/a"}
                ),
                _mock_usage(),
            )
        )

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_PAYLOAD_USED, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["functional_tests_passed"] is False


# ---------------------------------------------------------------------------
# validate — a crash that blocks the exploit is NOT a fix
# ---------------------------------------------------------------------------


class TestCrashIsNotAFix:
    def test_functional_failure_with_llm_blocked_verdict_still_reports_unconfirmed_overall(self):
        """
        The agent reports both fields honestly — it's the SUPERVISOR's job (per
        supervisor.py's completion gate) to require functional_tests_passed AND
        exploit_blocked before treating this as CONFIRMED. This test just pins
        that PatchValidationAgent doesn't conflate the two on its own.
        """
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[
                _tool_result("500"),  # crashed
                _tool_result("Internal Server Error"),
            ]
        )
        agent.llm.chat = MagicMock(
            return_value=(
                json.dumps(
                    {
                        "exploit_blocked": True,
                        "regression_introduced": True,
                        "details": "App crashed instead of rejecting cleanly",
                    }
                ),
                _mock_usage(),
            )
        )

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_PAYLOAD_USED, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is True
        assert result["functional_tests_passed"] is False
        assert result["regression_introduced"] is True


# ---------------------------------------------------------------------------
# validate — trace / payload edge cases
# ---------------------------------------------------------------------------


class TestReplayEdgeCases:
    def test_missing_trace_does_not_confirm_blocked(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(return_value=_tool_result("200"))
        agent.llm.chat = MagicMock()

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            side_effect=FileNotFoundError,
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is False
        agent.llm.chat.assert_not_called()

    def test_trace_with_no_execute_payload_event_does_not_confirm_blocked(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(return_value=_tool_result("200"))

        other_event = TraceEvent(
            trace_id=_TRACE_ID,
            timestamp="2026-07-25T00:00:00+00:00",
            team="red",
            agent="recon_agent",
            action="run",
            input={},
            output={},
            tokens_used=0,
            step_number=1,
        )

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace", return_value=[other_event]
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is False

    def test_unparseable_payload_does_not_confirm_blocked(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(return_value=_tool_result("200"))

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event("", _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is False

    def test_unbalanced_quotes_in_real_sqli_payload_does_not_crash(self):
        """shlex.split() raises ValueError on payloads like "1' OR 1=1--" — must degrade
        gracefully rather than crashing patch_validation_node."""
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(return_value=_tool_result("200"))
        agent.llm.chat = MagicMock()

        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(_UNBALANCED_QUOTE_PAYLOAD, _SUCCESS_INDICATORS)],
        ):
            result = agent.validate(
                _CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID
            )

        assert result["exploit_blocked"] is False
        agent.llm.chat.assert_not_called()

    def test_non_curl_tool_falls_back_to_curl_for_replay(self):
        agent = _make_agent()
        agent.transport.deploy_patch = MagicMock(return_value=_tool_result("patched"))
        agent.transport.run_tool = MagicMock(
            side_effect=[
                _tool_result("200"),
                _tool_result("400 rejected"),
            ]
        )
        agent.llm.chat = MagicMock(
            return_value=(
                json.dumps(
                    {"exploit_blocked": True, "regression_introduced": False, "details": "ok"}
                ),
                _mock_usage(),
            )
        )

        nikto_payload = "nikto -h http://localhost:8080/vulnerabilities/sqli/"
        with patch(
            "agents.blue_team.patch_validation_agent.load_trace",
            return_value=[_exploit_event(nikto_payload, _SUCCESS_INDICATORS)],
        ):
            agent.validate(_CONTAINER_ID, _PATCH_DIFF, _ALLOWED_PATHS, _HEALTH_URL, _TRACE_ID)

        replay_call = agent.transport.run_tool.call_args_list[1]
        assert replay_call.args[0] == "curl"


# ---------------------------------------------------------------------------
# _parse_json_response
# ---------------------------------------------------------------------------


class TestParseJsonResponse:
    def test_strips_markdown_fences(self):
        agent = _make_agent()
        verdict = {"exploit_blocked": True, "regression_introduced": False, "details": "ok"}
        fenced = f"```json\n{json.dumps(verdict)}\n```"
        result = agent._parse_json_response(fenced)
        assert result["exploit_blocked"] is True

    def test_missing_key_returns_unconfirmed(self):
        agent = _make_agent()
        incomplete = json.dumps({"exploit_blocked": True})
        result = agent._parse_json_response(incomplete)
        assert result["exploit_blocked"] is False
