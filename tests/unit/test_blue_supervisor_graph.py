# =============================================================================
# tests/unit/test_blue_supervisor_graph.py
# OWNER: Blue Team Hire
# MARKERS: unit (no Ollama or Docker — all agent calls mocked)
# PURPOSE: Tests for create_blue_team_graph() and node functions in
#          supervisor.py. Blue Team mirror of test_supervisor_graph.py.
# RUN: pytest tests/unit/test_blue_supervisor_graph.py -v
# =============================================================================

from unittest.mock import MagicMock, patch

import pytest

from agents.blue_team.blue_team import DefensePhase, PatchOutcome
from agents.blue_team.supervisor import (
    create_blue_team_graph,
    finalize_node,
    init_node,
    log_analysis_node,
    patch_generation_node,
    patch_validation_node,
    root_cause_node,
)

pytestmark = pytest.mark.unit


def _base_state(**overrides) -> dict:
    state = {
        "target_cve": "CVE-2024-1234",
        "target_url": "http://localhost:8080",
        "container_id": "blue-target-1",
        "exploit_timestamp": "2026-07-25T00:00:00+00:00",
        "functional_health_url": "http://localhost:8080/health",
        "exploit_replay_trace": "test-trace-id",
        "trace_id": "",
        "phase": DefensePhase.INIT,
        "step_count": 0,
        "token_count": 0,
        "patch_attempt_count": 0,
        "elapsed_seconds": 0.0,
        "attack_summary": None,
        "vulnerability_analysis": None,
        "patch_diff": None,
        "patch_confidence": None,
        "patch_strategy": None,
        "patch_applies_cleanly": False,
        "functional_tests_passed": False,
        "exploit_blocked": False,
        "regression_introduced": False,
        "outcome": None,
        "failure_reason": None,
        "supervisor_notes": [],
    }
    state.update(overrides)
    return state


_ATTACK_SUMMARY = {
    "target_endpoint": "/vulnerabilities/sqli/",
    "payload_observed": "id=1' OR 1=1--",
    "attack_goal_achieved": "database_access",
    "http_status_sequence": [200, 200],
    "evidence_excerpts": ["GET /vulnerabilities/sqli/?id=1' OR 1=1-- HTTP/1.1"],
    "confidence": 0.9,
}

_VULNERABILITY_ANALYSIS = {
    "cwe_classification": "CWE-89: SQL Injection",
    "vulnerable_file": "vulnerabilities/sqli/source/low.php",
    "vulnerable_function": "query",
    "vulnerable_line": 12,
    "missing_control": "No input sanitization before SQL query",
    "allowed_patch_paths": ["vulnerabilities/sqli/source/low.php"],
    "evidence": "string concatenation of $id into raw SQL",
    "confidence": 0.85,
}

_PATCH_RESULT = {
    "patch_diff": "--- a/low.php\n+++ b/low.php\n@@ -1 +1 @@\n-old\n+new\n",
    "confidence": 0.9,
    "strategy_used": "applied prepared statements",
    "rationale": "CWE-89 requires parameterization",
}

_VALIDATION_RESULT = {
    "patch_applies_cleanly": True,
    "functional_tests_passed": True,
    "exploit_blocked": True,
    "regression_introduced": False,
    "details": "Replay returned HTTP 400 validation error",
}


@patch("agents.blue_team.supervisor.TraceLogger")
class TestInitNode:
    def test_sets_fresh_engagement_fields(self, _mock_tracer):
        state = _base_state()
        result = init_node(state)
        assert result["phase"] == DefensePhase.INIT
        assert result["step_count"] == 0
        assert result["patch_attempt_count"] == 0
        assert result["trace_id"]
        assert result["supervisor_notes"] == []


@patch("agents.blue_team.supervisor.TraceLogger")
class TestLogAnalysisNode:
    def test_stores_attack_summary_and_advances_phase(self, _mock_tracer):
        state = _base_state()
        with patch("agents.blue_team.supervisor.LogAnalysisAgent") as MockAgent:
            MockAgent.return_value.analyze.return_value = _ATTACK_SUMMARY
            result = log_analysis_node(state)

        assert result["attack_summary"] == _ATTACK_SUMMARY
        assert result["phase"] == DefensePhase.LOG_ANALYSIS
        assert result["step_count"] == 1


@patch("agents.blue_team.supervisor.TraceLogger")
class TestRootCauseNode:
    def test_stores_vulnerability_analysis_and_advances_phase(self, _mock_tracer):
        state = _base_state(attack_summary=_ATTACK_SUMMARY)
        with patch("agents.blue_team.supervisor.RootCauseAgent") as MockAgent:
            MockAgent.return_value.analyze.return_value = _VULNERABILITY_ANALYSIS
            result = root_cause_node(state)

        assert result["vulnerability_analysis"] == _VULNERABILITY_ANALYSIS
        assert result["phase"] == DefensePhase.ROOT_CAUSE
        assert result["step_count"] == 1


@patch("agents.blue_team.supervisor.TraceLogger")
class TestPatchGenerationNode:
    def test_reads_source_and_stores_patch(self, _mock_tracer):
        state = _base_state(vulnerability_analysis=_VULNERABILITY_ANALYSIS, patch_attempt_count=0)

        with (
            patch("agents.blue_team.supervisor.BlueTeamTransport") as MockTransport,
            patch("agents.blue_team.supervisor.PatchGenerationAgent") as MockAgent,
        ):
            MockTransport.return_value.read_source_file.return_value = MagicMock(
                raw_output="<?php old code ?>"
            )
            MockAgent.return_value.generate_patch.return_value = _PATCH_RESULT
            result = patch_generation_node(state)

            MockAgent.return_value.generate_patch.assert_called_once_with(
                vulnerability_analysis=_VULNERABILITY_ANALYSIS,
                source_code="<?php old code ?>",
                attempt_number=1,
            )

        assert result["patch_diff"] == _PATCH_RESULT["patch_diff"]
        assert result["patch_confidence"] == 0.9
        assert result["patch_strategy"] == "applied prepared statements"
        assert result["phase"] == DefensePhase.PATCH_GENERATION

    def test_attempt_number_reflects_prior_attempts(self, _mock_tracer):
        state = _base_state(vulnerability_analysis=_VULNERABILITY_ANALYSIS, patch_attempt_count=2)

        with (
            patch("agents.blue_team.supervisor.BlueTeamTransport") as MockTransport,
            patch("agents.blue_team.supervisor.PatchGenerationAgent") as MockAgent,
        ):
            MockTransport.return_value.read_source_file.return_value = MagicMock(raw_output="")
            MockAgent.return_value.generate_patch.return_value = _PATCH_RESULT
            patch_generation_node(state)

            assert MockAgent.return_value.generate_patch.call_args.kwargs["attempt_number"] == 3


@patch("agents.blue_team.supervisor.TraceLogger")
@patch("agents.blue_team.supervisor.PatchGenerationAgent")
class TestPatchValidationNode:
    def test_stores_validation_result_and_logs_episode(self, MockPatchGenAgent, _mock_tracer):
        state = _base_state(
            vulnerability_analysis=_VULNERABILITY_ANALYSIS,
            patch_diff=_PATCH_RESULT["patch_diff"],
            patch_strategy=_PATCH_RESULT["strategy_used"],
        )

        with patch("agents.blue_team.supervisor.PatchValidationAgent") as MockValidator:
            MockValidator.return_value.validate.return_value = _VALIDATION_RESULT
            result = patch_validation_node(state)

        assert result["exploit_blocked"] is True
        assert result["functional_tests_passed"] is True
        assert result["phase"] == DefensePhase.PATCH_VALIDATION
        MockPatchGenAgent.return_value._log_episode.assert_called_once()
        assert MockPatchGenAgent.return_value._log_episode.call_args.kwargs["outcome"] == "success"

    def test_episode_log_failure_does_not_crash_pipeline(self, MockPatchGenAgent, _mock_tracer):
        state = _base_state(vulnerability_analysis=_VULNERABILITY_ANALYSIS)
        MockPatchGenAgent.return_value._log_episode.side_effect = RuntimeError("db down")

        with patch("agents.blue_team.supervisor.PatchValidationAgent") as MockValidator:
            MockValidator.return_value.validate.return_value = _VALIDATION_RESULT
            result = patch_validation_node(state)  # must not raise

        assert result["phase"] == DefensePhase.PATCH_VALIDATION


class TestFinalizeNode:
    def test_blocked_and_functional_is_success(self):
        state = _base_state(exploit_blocked=True, functional_tests_passed=True)
        result = finalize_node(state)
        assert result["outcome"] == PatchOutcome.SUCCESS
        assert result["phase"] == DefensePhase.COMPLETE

    def test_regression_marks_regression_outcome(self):
        state = _base_state(
            exploit_blocked=False, functional_tests_passed=False, regression_introduced=True
        )
        result = finalize_node(state)
        assert result["outcome"] == PatchOutcome.REGRESSION
        assert result["phase"] == DefensePhase.FAILED

    def test_exhausted_attempts_without_fix_is_failure(self):
        state = _base_state(exploit_blocked=False, functional_tests_passed=False)
        result = finalize_node(state)
        assert result["outcome"] == PatchOutcome.FAILURE
        assert result["phase"] == DefensePhase.FAILED


class TestCreateBlueTeamGraph:
    def test_compiles_without_error(self):
        graph = create_blue_team_graph()
        assert graph is not None
