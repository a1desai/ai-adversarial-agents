# =============================================================================
# tests/unit/test_log_analysis_agent.py
# OWNER: Blue Team Hire
# MARKERS: unit (no Ollama or Docker required — all external calls mocked)
# PURPOSE: Tests for LogAnalysisAgent.analyze() and helpers.
# RUN: pytest tests/unit/test_log_analysis_agent.py -v
# =============================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.blue_team.log_analysis_agent import LogAnalysisAgent
from agents.shared.mcp_transport import ToolResult
from hypervisor.packet_logger import AGENT_TO_TARGET, PacketRecord

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_SUMMARY = {
    "target_endpoint": "/vulnerabilities/sqli/",
    "payload_observed": "id=1' OR 1=1--",
    "attack_goal_achieved": "database_access",
    "http_status_sequence": [200, 200],
    "evidence_excerpts": ["GET /vulnerabilities/sqli/?id=1' OR 1=1-- HTTP/1.1\" 200"],
    "confidence": 0.9,
}


def _make_agent():
    with (
        patch("agents.blue_team.log_analysis_agent.get_client"),
        patch("agents.blue_team.log_analysis_agent.BlueTeamTransport"),
    ):
        return LogAnalysisAgent()


def _mock_usage():
    usage = MagicMock()
    usage.total = 100
    return usage


def _log_result(output: str) -> ToolResult:
    return ToolResult(
        tool="read_logs",
        success=True,
        raw_output=output,
        truncated=False,
        token_estimate=len(output) // 4,
    )


# ---------------------------------------------------------------------------
# analyze — happy path
# ---------------------------------------------------------------------------


class TestAnalyzeHappyPath:
    def test_returns_valid_summary(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("some log lines"))
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_SUMMARY), _mock_usage()))

        result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        assert result["target_endpoint"] == "/vulnerabilities/sqli/"
        assert result["attack_goal_achieved"] == "database_access"
        assert result["confidence"] == 0.9

    def test_all_required_keys_present(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("some log lines"))
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_SUMMARY), _mock_usage()))

        result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        for key in [
            "target_endpoint",
            "payload_observed",
            "attack_goal_achieved",
            "http_status_sequence",
            "evidence_excerpts",
            "confidence",
        ]:
            assert key in result

    def test_reads_logs_with_requested_time_window(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("logs"))
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_SUMMARY), _mock_usage()))

        agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00", time_window_seconds=120)

        agent.transport.read_logs.assert_called_once_with("blue-target-1", since_seconds=120)


# ---------------------------------------------------------------------------
# analyze — low confidence escalation
# ---------------------------------------------------------------------------


class TestLowConfidenceEscalation:
    def test_escalates_to_packet_capture_when_available(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("ambiguous logs"))

        low_confidence = {**_VALID_SUMMARY, "confidence": 0.1}
        high_confidence_after_packets = {**_VALID_SUMMARY, "confidence": 0.8}
        agent.llm.chat = MagicMock(
            side_effect=[
                (json.dumps(low_confidence), _mock_usage()),
                (json.dumps(high_confidence_after_packets), _mock_usage()),
            ]
        )

        packets = [
            PacketRecord(
                seq=0,
                timestamp="2026-07-25T00:00:00+00:00",
                connection_id="c1",
                direction=AGENT_TO_TARGET,
                src="10.0.0.1:5555",
                dst="10.0.0.2:80",
                length=42,
                data_b64="",
            )
        ]

        with patch(
            "agents.blue_team.log_analysis_agent.load_packets", return_value=packets
        ) as mock_load:
            result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        mock_load.assert_called_once_with("blue-target-1")
        assert agent.llm.chat.call_count == 2
        assert result["confidence"] == 0.8

    def test_keeps_low_confidence_result_when_no_packets_available(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("ambiguous logs"))

        low_confidence = {**_VALID_SUMMARY, "confidence": 0.1}
        agent.llm.chat = MagicMock(return_value=(json.dumps(low_confidence), _mock_usage()))

        with patch(
            "agents.blue_team.log_analysis_agent.load_packets",
            side_effect=FileNotFoundError,
        ):
            result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        assert agent.llm.chat.call_count == 1
        assert result["confidence"] == 0.1

    def test_confidence_at_threshold_does_not_escalate(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("logs"))
        at_threshold = {**_VALID_SUMMARY, "confidence": 0.3}
        agent.llm.chat = MagicMock(return_value=(json.dumps(at_threshold), _mock_usage()))

        result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        assert agent.llm.chat.call_count == 1
        assert result["confidence"] == 0.3


# ---------------------------------------------------------------------------
# JSON parsing fallback
# ---------------------------------------------------------------------------


class TestParseJsonResponse:
    def test_non_json_response_returns_zero_confidence_summary(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("logs"))
        agent.llm.chat = MagicMock(return_value=("not json at all", _mock_usage()))

        result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        assert result["confidence"] == 0.0
        assert result["target_endpoint"] == ""

    def test_strips_markdown_fences(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("logs"))
        fenced = f"```json\n{json.dumps(_VALID_SUMMARY)}\n```"
        agent.llm.chat = MagicMock(return_value=(fenced, _mock_usage()))

        result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        assert result["target_endpoint"] == "/vulnerabilities/sqli/"

    def test_missing_key_falls_back_to_zero_confidence(self):
        agent = _make_agent()
        agent.transport.read_logs = MagicMock(return_value=_log_result("logs"))
        incomplete = {k: v for k, v in _VALID_SUMMARY.items() if k != "confidence"}
        agent.llm.chat = MagicMock(return_value=(json.dumps(incomplete), _mock_usage()))

        result = agent.analyze("blue-target-1", "2026-07-25T00:00:00+00:00")

        assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# _validate_output
# ---------------------------------------------------------------------------


class TestValidateOutput:
    def test_valid_summary_passes(self):
        agent = _make_agent()
        assert agent._validate_output(_VALID_SUMMARY) is True

    def test_missing_key_raises(self):
        agent = _make_agent()
        incomplete = {k: v for k, v in _VALID_SUMMARY.items() if k != "confidence"}
        with pytest.raises(ValueError, match="confidence"):
            agent._validate_output(incomplete)
