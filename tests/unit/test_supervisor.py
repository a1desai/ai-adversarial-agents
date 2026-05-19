# =============================================================================
# tests/unit/test_supervisor.py
# OWNER: Red Team Hire / Lead
# MARKERS: unit (no Ollama or Docker required)
# PURPOSE: Tests for agents/red_team/supervisor.py — routing logic and
#          hard-cap enforcement.
# RUN: pytest tests/unit/test_supervisor.py -v
# =============================================================================

from langgraph.graph import END

from agents.red_team.state import AttackPhase, AttackOutcome
from agents.red_team.supervisor import (
    supervisor_route,
    MAX_STEPS,
    MAX_TOKENS,
    MAX_RETRIES,
)


def _base_state(**overrides) -> dict:
    """Minimal RedTeamState — overrides only what each test needs."""
    state = {
        "target_url":              "http://localhost:8080",
        "target_cve":              None,
        "trace_id":                "test-trace-id",
        "phase":                   AttackPhase.INIT,
        "step_count":              0,
        "token_count":             0,
        "retry_count":             0,
        "elapsed_seconds":         0.0,
        "recon_summary":           None,
        "cve_matches":             [],
        "attack_plan":             None,
        "payload_used":            None,
        "server_response":         None,
        "exploit_claimed_success": None,
        "grader_confirmed":        False,
        "attack_goals_achieved":   [],
        "outcome":                 None,
        "failure_reason":          None,
        "supervisor_notes":        [],
    }
    state.update(overrides)
    return state


# ---------------------------------------------------------------------------
# Hard caps (must run BEFORE any phase routing)
# ---------------------------------------------------------------------------

class TestHardCaps:

    def test_max_steps_terminates(self):
        state = _base_state(step_count=MAX_STEPS, phase=AttackPhase.RECON)
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.TIMEOUT

    def test_max_tokens_terminates(self):
        state = _base_state(token_count=MAX_TOKENS, phase=AttackPhase.RECON)
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.TIMEOUT

    def test_max_retries_terminates(self):
        state = _base_state(retry_count=MAX_RETRIES, phase=AttackPhase.EXPLOITATION)
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.FAILURE


# ---------------------------------------------------------------------------
# Phase routing — INIT and RECON
# ---------------------------------------------------------------------------

class TestPhaseRoutingInitRecon:

    def test_init_routes_to_recon(self):
        state = _base_state(phase=AttackPhase.INIT)
        assert supervisor_route(state) == "recon_node"

    def test_recon_with_no_ports_terminates(self):
        state = _base_state(phase=AttackPhase.RECON, recon_summary={"ports": []})
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.FAILURE

    def test_recon_with_no_summary_terminates(self):
        state = _base_state(phase=AttackPhase.RECON, recon_summary=None)
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.FAILURE

    def test_recon_with_ports_routes_to_exploitation(self):
        state = _base_state(
            phase=AttackPhase.RECON,
            recon_summary={"ports": [{"port": "80/tcp", "service": "http"}]},
        )
        assert supervisor_route(state) == "exploitation_node"


# ---------------------------------------------------------------------------
# Phase routing — EXPLOITATION (the bug we're fixing)
# ---------------------------------------------------------------------------

class TestExploitationRouting:
    """The original bug: this branch always returned 'exploitation_node'."""

    def _exploit_state(self, **overrides) -> dict:
        defaults = {
            "phase":          AttackPhase.EXPLOITATION,
            "recon_summary":  {"ports": [{"port": "80/tcp", "service": "http"}]},
            "attack_plan":    {"target_service": "http", "technique": "sqli"},
        }
        defaults.update(overrides)
        return _base_state(**defaults)

    def test_claimed_success_with_valid_plan_routes_to_verification(self):
        """The success path — previously broken, always returned exploitation_node."""
        state = self._exploit_state(exploit_claimed_success=True)
        assert supervisor_route(state) == "verification_node"

    def test_claimed_failure_routes_back_to_exploitation_and_increments_retries(self):
        state = self._exploit_state(exploit_claimed_success=False, retry_count=0)
        assert supervisor_route(state) == "exploitation_node"
        assert state["retry_count"] == 1

    def test_plan_targeting_undiscovered_service_is_rejected(self):
        """Evaluator gate: plan targeting service not in recon → retry."""
        state = self._exploit_state(
            attack_plan={"target_service": "ftp", "technique": "anon-login"},
            exploit_claimed_success=True,  # would route to verification if plan were valid
        )
        # Plan validation runs first; gate rejects → retry
        assert supervisor_route(state) == "exploitation_node"
        assert state["retry_count"] == 1

    def test_no_attack_plan_is_rejected(self):
        state = self._exploit_state(attack_plan=None)
        assert supervisor_route(state) == "exploitation_node"


# ---------------------------------------------------------------------------
# Phase routing — VERIFICATION
# ---------------------------------------------------------------------------

class TestVerificationRouting:

    def test_grader_confirmed_marks_complete(self):
        state = _base_state(phase=AttackPhase.VERIFICATION, grader_confirmed=True)
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.SUCCESS
        assert state["phase"]   == AttackPhase.COMPLETE

    def test_grader_rejected_marks_failed(self):
        """Verification rejecting a claimed success → ungrounded → FAILURE."""
        state = _base_state(phase=AttackPhase.VERIFICATION, grader_confirmed=False)
        assert supervisor_route(state) == END
        assert state["outcome"] == AttackOutcome.FAILURE
        assert "Verification rejected" in state["failure_reason"]


# ---------------------------------------------------------------------------
# Terminal phases
# ---------------------------------------------------------------------------

class TestTerminalPhases:

    def test_complete_phase_returns_end(self):
        state = _base_state(phase=AttackPhase.COMPLETE)
        assert supervisor_route(state) == END

    def test_failed_phase_returns_end(self):
        state = _base_state(phase=AttackPhase.FAILED)
        assert supervisor_route(state) == END
