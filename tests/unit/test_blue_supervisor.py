# =============================================================================
# tests/unit/test_blue_supervisor.py
# OWNER: Blue Team Hire
# MARKERS: unit (no Ollama or Docker required)
# PURPOSE: Tests for agents/blue_team/supervisor.py — routing logic and
#          hard-cap enforcement. Blue Team mirror of test_supervisor.py.
# RUN: pytest tests/unit/test_blue_supervisor.py -v
# =============================================================================

import pytest
from langgraph.graph import END

from agents.blue_team.blue_team import DefensePhase, PatchOutcome
from agents.blue_team.supervisor import (
    MAX_PATCH_ATTEMPTS,
    MAX_SECONDS,
    MAX_STEPS,
    MAX_TOKENS,
    MIN_CONFIDENCE_DEPLOY,
    supervisor_route,
)

pytestmark = pytest.mark.unit


def _base_state(**overrides) -> dict:
    """Minimal BlueTeamState — overrides only what each test needs."""
    state = {
        "target_cve": "CVE-2024-1234",
        "target_url": "http://localhost:8080",
        "container_id": "blue-target-1",
        "exploit_timestamp": "2026-07-25T00:00:00+00:00",
        "functional_health_url": "http://localhost:8080/health",
        "exploit_replay_trace": "test-trace-id",
        "trace_id": "test-trace-id",
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


# ---------------------------------------------------------------------------
# Hard caps (must run BEFORE any phase routing)
# ---------------------------------------------------------------------------


class TestHardCaps:
    def test_max_steps_terminates(self):
        state = _base_state(step_count=MAX_STEPS, phase=DefensePhase.ROOT_CAUSE)
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.TIMEOUT

    def test_max_tokens_terminates(self):
        state = _base_state(token_count=MAX_TOKENS, phase=DefensePhase.ROOT_CAUSE)
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.TIMEOUT

    def test_max_seconds_terminates(self):
        state = _base_state(elapsed_seconds=MAX_SECONDS, phase=DefensePhase.ROOT_CAUSE)
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.TIMEOUT

    def test_max_patch_attempts_terminates(self):
        state = _base_state(
            patch_attempt_count=MAX_PATCH_ATTEMPTS, phase=DefensePhase.PATCH_GENERATION
        )
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.FAILURE


# ---------------------------------------------------------------------------
# Phase routing — INIT and LOG_ANALYSIS
# ---------------------------------------------------------------------------


class TestPhaseRoutingInitLogAnalysis:
    def test_init_routes_to_log_analysis(self):
        state = _base_state(phase=DefensePhase.INIT)
        assert supervisor_route(state) == "log_analysis_node"

    def test_log_analysis_with_no_summary_terminates(self):
        state = _base_state(phase=DefensePhase.LOG_ANALYSIS, attack_summary=None)
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.FAILURE

    def test_log_analysis_with_summary_routes_to_root_cause(self):
        state = _base_state(phase=DefensePhase.LOG_ANALYSIS, attack_summary=_ATTACK_SUMMARY)
        assert supervisor_route(state) == "root_cause_node"


# ---------------------------------------------------------------------------
# Phase routing — ROOT_CAUSE
# ---------------------------------------------------------------------------


class TestPhaseRoutingRootCause:
    def test_root_cause_with_no_analysis_terminates(self):
        state = _base_state(phase=DefensePhase.ROOT_CAUSE, vulnerability_analysis=None)
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.FAILURE

    def test_root_cause_with_empty_allowed_paths_terminates(self):
        state = _base_state(
            phase=DefensePhase.ROOT_CAUSE,
            vulnerability_analysis={**_VULNERABILITY_ANALYSIS, "allowed_patch_paths": []},
        )
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.FAILURE

    def test_root_cause_with_valid_analysis_routes_to_patch_generation(self):
        state = _base_state(
            phase=DefensePhase.ROOT_CAUSE, vulnerability_analysis=_VULNERABILITY_ANALYSIS
        )
        assert supervisor_route(state) == "patch_generation_node"


# ---------------------------------------------------------------------------
# Phase routing — PATCH_GENERATION (confidence gate)
# ---------------------------------------------------------------------------


class TestPatchGenerationRouting:
    def test_low_confidence_retries_and_increments_attempts(self):
        state = _base_state(
            phase=DefensePhase.PATCH_GENERATION,
            patch_confidence=MIN_CONFIDENCE_DEPLOY - 0.1,
            patch_attempt_count=0,
        )
        assert supervisor_route(state) == "patch_generation_node"
        assert state["patch_attempt_count"] == 1

    def test_missing_confidence_retries(self):
        state = _base_state(phase=DefensePhase.PATCH_GENERATION, patch_confidence=None)
        assert supervisor_route(state) == "patch_generation_node"

    def test_confidence_at_threshold_routes_to_validation(self):
        state = _base_state(
            phase=DefensePhase.PATCH_GENERATION, patch_confidence=MIN_CONFIDENCE_DEPLOY
        )
        assert supervisor_route(state) == "patch_validation_node"

    def test_high_confidence_routes_to_validation(self):
        state = _base_state(phase=DefensePhase.PATCH_GENERATION, patch_confidence=0.9)
        assert supervisor_route(state) == "patch_validation_node"


# ---------------------------------------------------------------------------
# Phase routing — PATCH_VALIDATION (completion gate)
# ---------------------------------------------------------------------------


class TestPatchValidationRouting:
    def test_blocked_and_functional_routes_to_finalize(self):
        state = _base_state(
            phase=DefensePhase.PATCH_VALIDATION,
            exploit_blocked=True,
            functional_tests_passed=True,
        )
        assert supervisor_route(state) == "finalize_node"

    def test_exploit_not_blocked_retries_and_increments_attempts(self):
        state = _base_state(
            phase=DefensePhase.PATCH_VALIDATION,
            exploit_blocked=False,
            functional_tests_passed=True,
            patch_attempt_count=0,
        )
        assert supervisor_route(state) == "patch_generation_node"
        assert state["patch_attempt_count"] == 1

    def test_functional_tests_failed_retries_even_if_exploit_blocked(self):
        """A crash that blocks the exploit is NOT a fix."""
        state = _base_state(
            phase=DefensePhase.PATCH_VALIDATION,
            exploit_blocked=True,
            functional_tests_passed=False,
            patch_attempt_count=0,
        )
        assert supervisor_route(state) == "patch_generation_node"
        assert state["patch_attempt_count"] == 1


# ---------------------------------------------------------------------------
# Terminal phases
# ---------------------------------------------------------------------------


class TestTerminalPhases:
    def test_complete_phase_returns_end(self):
        state = _base_state(phase=DefensePhase.COMPLETE)
        assert supervisor_route(state) == END

    def test_failed_phase_returns_end(self):
        state = _base_state(phase=DefensePhase.FAILED)
        assert supervisor_route(state) == END
