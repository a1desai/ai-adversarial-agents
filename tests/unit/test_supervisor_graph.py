# =============================================================================
# tests/unit/test_supervisor_graph.py
# OWNER: Red Team Hire
# MARKERS: unit (no Ollama or Docker — all agent calls mocked)
# PURPOSE: Tests for create_red_team_graph() and node functions in supervisor.py
# RUN: pytest tests/unit/test_supervisor_graph.py -v
# =============================================================================

from unittest.mock import patch

import pytest

from agents.red_team.state import AttackPhase
from agents.red_team.supervisor import (
    create_red_team_graph,
    exploitation_node,
    init_node,
    recon_node,
    verification_node,
)

pytestmark = pytest.mark.unit


def _base_state(**overrides) -> dict:
    state = {
        "target_url": "http://localhost:8080",
        "target_cve": None,
        "trace_id": "",
        "phase": AttackPhase.INIT,
        "step_count": 0,
        "token_count": 0,
        "retry_count": 0,
        "elapsed_seconds": 0.0,
        "recon_summary": None,
        "cve_matches": [],
        "attack_plan": None,
        "payload_used": None,
        "server_response": None,
        "exploit_claimed_success": None,
        "grader_confirmed": False,
        "attack_goals_achieved": [],
        "outcome": None,
        "failure_reason": None,
        "supervisor_notes": [],
    }
    state.update(overrides)
    return state


_RECON_SUMMARY = {
    "ports": [{"port": "80/tcp", "state": "open", "service": "http", "version": "Apache 2.4"}],
    "technologies": ["PHP 7.4", "MySQL 5.7"],
    "directories": ["/login.php"],
    "potential_entry_points": ["/login.php"],
    "confidence": 0.9,
}

_ATTACK_PLAN = {
    "target_service": "http",
    "target_endpoint": "/login.php",
    "cve_id": "CVE-2021-42013",
    "technique": "SQL injection via UNION",
    "confidence": 0.85,
    "rationale": "Procedural memory match.",
}

_EXECUTE_RESULT = {
    "payload_used": "' OR 1=1--",
    "server_response": "Welcome admin",
    "success_indicators": ["admin panel visible"],
    "outcome": "SUCCESS",
    "confidence": 0.9,
}

_VERIFY_RESULT = {
    "confirmed": True,
    "attack_goals_achieved": ["unauthorized_login"],
    "grader_response": '{"status": "success"}',
    "confidence": 0.95,
}


# ---------------------------------------------------------------------------
# create_red_team_graph — compilation
# ---------------------------------------------------------------------------


class TestCreateRedTeamGraph:
    def test_graph_compiles(self):
        graph = create_red_team_graph()
        assert graph is not None

    def test_graph_has_expected_nodes(self):
        graph = create_red_team_graph()
        node_names = set(graph.get_graph().nodes.keys())
        for name in ("init_node", "recon_node", "exploitation_node", "verification_node"):
            assert name in node_names


# ---------------------------------------------------------------------------
# init_node
# ---------------------------------------------------------------------------


class TestInitNode:
    def test_sets_trace_id(self):
        state = _base_state()
        result = init_node(state)
        assert result["trace_id"] != ""

    def test_resets_counters(self):
        state = _base_state(step_count=5, token_count=100, retry_count=2)
        result = init_node(state)
        assert result["step_count"] == 0
        assert result["token_count"] == 0
        assert result["retry_count"] == 0

    def test_sets_init_phase(self):
        state = _base_state()
        result = init_node(state)
        assert result["phase"] == AttackPhase.INIT


# ---------------------------------------------------------------------------
# recon_node
# ---------------------------------------------------------------------------


class TestReconNode:
    def test_stores_recon_summary(self):
        state = _base_state(supervisor_notes=[])
        with (
            patch("agents.red_team.supervisor.ReconAgent") as MockRecon,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            MockRecon.return_value.run.return_value = _RECON_SUMMARY
            result = recon_node(state)

        assert result["recon_summary"] == _RECON_SUMMARY
        assert result["phase"] == AttackPhase.RECON

    def test_increments_step_count(self):
        state = _base_state(supervisor_notes=[])
        with (
            patch("agents.red_team.supervisor.ReconAgent") as MockRecon,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            MockRecon.return_value.run.return_value = _RECON_SUMMARY
            result = recon_node(state)

        assert result["step_count"] == 1

    def test_appends_supervisor_note(self):
        state = _base_state(supervisor_notes=[])
        with (
            patch("agents.red_team.supervisor.ReconAgent") as MockRecon,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            MockRecon.return_value.run.return_value = _RECON_SUMMARY
            result = recon_node(state)

        assert any("Recon complete" in note for note in result["supervisor_notes"])


# ---------------------------------------------------------------------------
# exploitation_node
# ---------------------------------------------------------------------------


class TestExploitationNode:
    def test_stores_plan_and_result(self):
        state = _base_state(recon_summary=_RECON_SUMMARY, supervisor_notes=[])
        with (
            patch("agents.red_team.supervisor.ExploitationAgent") as MockAgent,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            instance = MockAgent.return_value
            instance.plan_attack.return_value = _ATTACK_PLAN
            instance.execute_payload.return_value = _EXECUTE_RESULT
            result = exploitation_node(state)

        assert result["attack_plan"] == _ATTACK_PLAN
        assert result["payload_used"] == "' OR 1=1--"
        assert result["exploit_claimed_success"] is True
        assert result["phase"] == AttackPhase.EXPLOITATION

    def test_sets_target_cve_from_plan(self):
        state = _base_state(recon_summary=_RECON_SUMMARY, supervisor_notes=[])
        with (
            patch("agents.red_team.supervisor.ExploitationAgent") as MockAgent,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            instance = MockAgent.return_value
            instance.plan_attack.return_value = _ATTACK_PLAN
            instance.execute_payload.return_value = _EXECUTE_RESULT
            result = exploitation_node(state)

        assert result["target_cve"] == "CVE-2021-42013"

    def test_failure_outcome_sets_claimed_false(self):
        state = _base_state(recon_summary=_RECON_SUMMARY, supervisor_notes=[])
        failed_result = {**_EXECUTE_RESULT, "outcome": "FAILURE"}
        with (
            patch("agents.red_team.supervisor.ExploitationAgent") as MockAgent,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            instance = MockAgent.return_value
            instance.plan_attack.return_value = _ATTACK_PLAN
            instance.execute_payload.return_value = failed_result
            result = exploitation_node(state)

        assert result["exploit_claimed_success"] is False


# ---------------------------------------------------------------------------
# verification_node
# ---------------------------------------------------------------------------


class TestVerificationNode:
    def test_confirmed_exploit(self):
        state = _base_state(
            payload_used="' OR 1=1--",
            server_response="Welcome admin",
            exploit_claimed_success=True,
            target_cve="CVE-2021-42013",
            supervisor_notes=[],
        )
        with (
            patch("agents.red_team.supervisor.VerificationAgent") as MockAgent,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            MockAgent.return_value.verify.return_value = _VERIFY_RESULT
            result = verification_node(state)

        assert result["grader_confirmed"] is True
        assert result["attack_goals_achieved"] == ["unauthorized_login"]
        assert result["phase"] == AttackPhase.VERIFICATION

    def test_unconfirmed_exploit(self):
        state = _base_state(
            payload_used="test",
            server_response="403",
            exploit_claimed_success=True,
            target_cve="CVE-2021-42013",
            supervisor_notes=[],
        )
        unconfirmed = {**_VERIFY_RESULT, "confirmed": False, "attack_goals_achieved": []}
        with (
            patch("agents.red_team.supervisor.VerificationAgent") as MockAgent,
            patch("agents.red_team.supervisor._log_trace"),
        ):
            MockAgent.return_value.verify.return_value = unconfirmed
            result = verification_node(state)

        assert result["grader_confirmed"] is False
        assert result["attack_goals_achieved"] == []
