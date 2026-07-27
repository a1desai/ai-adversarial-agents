# =============================================================================
# tests/unit/test_root_cause_agent.py
# OWNER: Blue Team Hire
# MARKERS: unit (no Ollama or Docker required — all external calls mocked)
# PURPOSE: Tests for RootCauseAgent.analyze() and helpers.
# RUN: pytest tests/unit/test_root_cause_agent.py -v
# =============================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.blue_team.root_cause_agent import RootCauseAgent
from agents.shared.mcp_transport import ToolResult

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_ATTACK_SUMMARY = {
    "target_endpoint": "/vulnerabilities/sqli/",
    "payload_observed": "id=1' OR 1=1--",
    "attack_goal_achieved": "database_access",
    "http_status_sequence": [200, 200],
    "evidence_excerpts": ["GET /vulnerabilities/sqli/?id=1' OR 1=1-- HTTP/1.1\" 200"],
    "confidence": 0.9,
}

_VALID_ANALYSIS = {
    "cwe_classification": "CWE-89: SQL Injection",
    "vulnerable_file": "vulnerabilities/sqli/source/low.php",
    "vulnerable_function": "query",
    "vulnerable_line": 12,
    "missing_control": "No input sanitization before SQL query",
    "allowed_patch_paths": ["vulnerabilities/sqli/source/low.php"],
    "evidence": "string concatenation of $id into raw SQL",
    "confidence": 0.85,
}

_EMPTY_MEMORY = {"procedural": [], "episodic": [], "knowledge": []}


def _make_agent():
    with (
        patch("agents.blue_team.root_cause_agent.get_client"),
        patch("agents.blue_team.root_cause_agent.BlueTeamTransport"),
    ):
        return RootCauseAgent()


def _mock_usage():
    usage = MagicMock()
    usage.total = 90
    return usage


def _source_result(output: str, success: bool = True) -> ToolResult:
    return ToolResult(
        tool="read_source",
        success=success,
        raw_output=output,
        truncated=False,
        token_estimate=len(output) // 4,
    )


# ---------------------------------------------------------------------------
# analyze — happy path
# ---------------------------------------------------------------------------


class TestAnalyzeHappyPath:
    def test_returns_valid_analysis_with_explicit_candidates(self):
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(
            return_value=_source_result("<?php $q = 'SELECT * FROM users WHERE id=' . $id; ?>")
        )
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_ANALYSIS), _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            result = agent.analyze(
                _ATTACK_SUMMARY,
                "blue-target-1",
                candidate_files=["vulnerabilities/sqli/source/low.php"],
            )

        assert result["cwe_classification"] == "CWE-89: SQL Injection"
        assert result["allowed_patch_paths"] == ["vulnerabilities/sqli/source/low.php"]

    def test_all_required_keys_present(self):
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(return_value=_source_result("<?php ?>"))
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_ANALYSIS), _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            result = agent.analyze(_ATTACK_SUMMARY, "blue-target-1")

        for key in [
            "cwe_classification",
            "vulnerable_file",
            "vulnerable_function",
            "vulnerable_line",
            "missing_control",
            "allowed_patch_paths",
            "evidence",
            "confidence",
        ]:
            assert key in result

    def test_infers_candidate_file_from_endpoint_when_none_given(self):
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(return_value=_source_result("<?php ?>"))
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_ANALYSIS), _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            agent.analyze(_ATTACK_SUMMARY, "blue-target-1")

        agent.transport.read_source_file.assert_called_once_with(
            "blue-target-1", "vulnerabilities/sqli/index.php"
        )


# ---------------------------------------------------------------------------
# _infer_candidate_files
# ---------------------------------------------------------------------------


class TestInferCandidateFiles:
    def test_strips_query_string(self):
        agent = _make_agent()
        result = agent._infer_candidate_files({"target_endpoint": "/login.php?id=1"})
        assert result == ["login.php"]

    def test_directory_path_appends_index_php(self):
        agent = _make_agent()
        result = agent._infer_candidate_files({"target_endpoint": "/admin/"})
        assert result == ["admin/index.php"]

    def test_empty_endpoint_returns_empty_list(self):
        agent = _make_agent()
        result = agent._infer_candidate_files({"target_endpoint": ""})
        assert result == []


# ---------------------------------------------------------------------------
# Source reading — unreadable files degrade gracefully
# ---------------------------------------------------------------------------


class TestReadSources:
    def test_unreadable_file_does_not_crash(self):
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(return_value=_source_result("", success=False))
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_ANALYSIS), _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            result = agent.analyze(
                _ATTACK_SUMMARY, "blue-target-1", candidate_files=["missing.php"]
            )

        assert result["cwe_classification"] == "CWE-89: SQL Injection"


# ---------------------------------------------------------------------------
# JSON parsing fallback
# ---------------------------------------------------------------------------


class TestParseJsonResponse:
    def test_non_json_response_falls_back_using_candidate_file(self):
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(return_value=_source_result("<?php ?>"))
        agent.llm.chat = MagicMock(return_value=("not json", _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            result = agent.analyze(
                _ATTACK_SUMMARY, "blue-target-1", candidate_files=["vulnerable.php"]
            )

        assert result["confidence"] == 0.0
        assert result["allowed_patch_paths"] == ["vulnerable.php"]

    def test_non_json_response_with_no_candidates_does_not_crash(self):
        """
        No candidates at all means there's genuinely nothing to patch. This must NOT
        raise out of analyze() — the supervisor's root_cause_node calls agent.analyze()
        with no try/except (PR #61), so an uncaught ValueError here would crash the
        whole LangGraph engagement instead of cleanly routing to FAILURE via the
        supervisor's existing "no allowed_patch_paths" gate.
        """
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(return_value=_source_result("<?php ?>"))
        agent.llm.chat = MagicMock(return_value=("not json", _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            result = agent.analyze({"target_endpoint": ""}, "blue-target-1")  # must not raise

        assert result["allowed_patch_paths"] == []
        assert result["confidence"] == 0.0

    def test_strips_markdown_fences(self):
        agent = _make_agent()
        agent.transport.read_source_file = MagicMock(return_value=_source_result("<?php ?>"))
        fenced = f"```json\n{json.dumps(_VALID_ANALYSIS)}\n```"
        agent.llm.chat = MagicMock(return_value=(fenced, _mock_usage()))

        with patch(
            "agents.blue_team.root_cause_agent.parallel_retrieval", return_value=_EMPTY_MEMORY
        ):
            result = agent.analyze(_ATTACK_SUMMARY, "blue-target-1")

        assert result["cwe_classification"] == "CWE-89: SQL Injection"


# ---------------------------------------------------------------------------
# _validate_output
# ---------------------------------------------------------------------------


class TestValidateOutput:
    def test_valid_analysis_passes(self):
        agent = _make_agent()
        assert agent._validate_output(_VALID_ANALYSIS) is True

    def test_missing_key_raises(self):
        agent = _make_agent()
        incomplete = {k: v for k, v in _VALID_ANALYSIS.items() if k != "confidence"}
        with pytest.raises(ValueError, match="confidence"):
            agent._validate_output(incomplete)

    def test_empty_allowed_patch_paths_raises(self):
        agent = _make_agent()
        invalid = {**_VALID_ANALYSIS, "allowed_patch_paths": []}
        with pytest.raises(ValueError, match="allowed_patch_paths"):
            agent._validate_output(invalid)

    def test_non_list_allowed_patch_paths_raises(self):
        agent = _make_agent()
        invalid = {**_VALID_ANALYSIS, "allowed_patch_paths": "not-a-list.php"}
        with pytest.raises(ValueError, match="allowed_patch_paths"):
            agent._validate_output(invalid)
