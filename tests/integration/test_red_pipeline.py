# =============================================================================
# tests/integration/test_red_pipeline.py
# OWNER: Eval Hire
# PURPOSE: End-to-end integration test for the Red Team LangGraph pipeline.
#          Mocks the three Ollama-backed agents (Recon, Exploitation,
#          Verification) so the compiled graph runs a full
#          recon -> exploitation -> verification -> finalize path with NO
#          network / GPU / Docker involvement.
# REFERENCE: Issue #69 — Integration tests (Red Team pipeline)
# NOTE: AI-assisted (drafted with Claude), human-reviewed.
# =============================================================================

import pytest

from agents.red_team import supervisor as sup
from agents.red_team.state import AttackOutcome, AttackPhase

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_agents(monkeypatch, recon_cls, exploit_cls, verify_cls):
    """Swaps the real agent classes referenced inside the supervisor module for
    the supplied fakes, and neutralizes the disk-writing trace logger."""
    monkeypatch.setattr(sup, "ReconAgent", recon_cls)
    monkeypatch.setattr(sup, "ExploitationAgent", exploit_cls)
    monkeypatch.setattr(sup, "VerificationAgent", verify_cls)
    # _log_trace writes JSONL to evaluation/traces/; keep the test hermetic.
    monkeypatch.setattr(sup, "_log_trace", lambda *a, **k: None)


def _initial_state(target_url="http://localhost:8080", target_cve="CVE-2024-0001"):
    # init_node fills in trace_id / counters / notes; we only seed the target.
    return {"target_url": target_url, "target_cve": target_cve}


# ---------------------------------------------------------------------------
# Happy path: grader confirms the exploit -> SUCCESS
# ---------------------------------------------------------------------------


def test_happy_path_reaches_success(monkeypatch, fake_red_agents):
    _patch_agents(
        monkeypatch,
        fake_red_agents["ReconAgent"],
        fake_red_agents["ExploitationAgent"],
        fake_red_agents["VerificationAgent"],
    )

    graph = sup.create_red_team_graph()
    final = graph.invoke(_initial_state())

    assert final["outcome"] == AttackOutcome.SUCCESS
    assert final["phase"] == AttackPhase.COMPLETE
    assert final["grader_confirmed"] is True
    assert final["exploit_claimed_success"] is True
    assert final["attack_goals_achieved"] == ["database_access"]
    # A trace id was minted and every phase left a supervisor note.
    assert final["trace_id"]
    assert any("Verification" in note for note in final["supervisor_notes"])
    # No failure recorded on the happy path.
    assert final.get("failure_reason") is None


# ---------------------------------------------------------------------------
# Grader-rejected path: exploit claimed but grader says no -> FAILURE
# ---------------------------------------------------------------------------


def test_grader_rejection_reaches_failure(monkeypatch, fake_red_agents):
    class RejectingVerifier(fake_red_agents["VerificationAgent"]):
        confirmed = False
        attack_goals_achieved = []
        confidence = 0.0  # below the 0.7 fallback threshold in finalize_node

    _patch_agents(
        monkeypatch,
        fake_red_agents["ReconAgent"],
        fake_red_agents["ExploitationAgent"],
        RejectingVerifier,
    )

    graph = sup.create_red_team_graph()
    final = graph.invoke(_initial_state())

    # Exploitation still self-reported success, but the grader gate rejected it.
    assert final["exploit_claimed_success"] is True
    assert final["grader_confirmed"] is False
    assert final["outcome"] == AttackOutcome.FAILURE
    assert final["phase"] == AttackPhase.FAILED
    assert final["failure_reason"] == "Verification rejected claimed exploit"


# ---------------------------------------------------------------------------
# Hard-cap enforcement: exploitation never confirms -> retries exhausted
# ---------------------------------------------------------------------------


def test_never_confirming_exploit_hits_hard_cap(monkeypatch, fake_red_agents):
    # NOTE: The supervisor's retry-count increment and _terminate() writes happen
    # inside supervisor_route(), which is a LangGraph *conditional-edge* function.
    # LangGraph only persists state returned by NODES, so those edge-function
    # writes (retry_count += 1, outcome, failure_reason) are discarded between
    # supersteps. The net effect: an exploit that never self-confirms loops on
    # exploitation_node until the step_count hard cap (set inside the node, so it
    # DOES persist) forces termination. This test locks in that the pipeline is
    # guaranteed to terminate on a hard cap and never falsely reaches SUCCESS.
    class NeverSucceedsExploit(fake_red_agents["ExploitationAgent"]):
        exec_outcome = "FAILURE"  # -> exploit_claimed_success False every attempt
        exec_confidence = 0.1

    # Verifier must never be reached: the exploit never claims success.
    class ExplodingVerifier(fake_red_agents["VerificationAgent"]):
        def verify(self, *a, **k):
            raise AssertionError("verification_node must not run without a claimed exploit")

    _patch_agents(
        monkeypatch,
        fake_red_agents["ReconAgent"],
        NeverSucceedsExploit,
        ExplodingVerifier,
    )

    graph = sup.create_red_team_graph()
    final = graph.invoke(_initial_state())  # returns => graph halted, no infinite loop

    # The step-count hard cap (persisted, written in exploitation_node) fired.
    assert final["step_count"] >= sup.MAX_STEPS
    assert final["exploit_claimed_success"] is False
    # Crucially, an unconfirmed exploit is never reported as a success.
    assert final.get("outcome") != AttackOutcome.SUCCESS
    assert final.get("grader_confirmed") in (False, None)


# ---------------------------------------------------------------------------
# Recon dead-end: no services discovered -> immediate FAILURE, no exploitation
# ---------------------------------------------------------------------------


def test_empty_recon_terminates_before_exploitation(monkeypatch, fake_red_agents):
    class EmptyRecon(fake_red_agents["ReconAgent"]):
        ports = []
        confidence = 0.0

    class ExplodingExploit(fake_red_agents["ExploitationAgent"]):
        def plan_attack(self, *a, **k):
            raise AssertionError("exploitation must not run when recon found no services")

    _patch_agents(
        monkeypatch,
        EmptyRecon,
        ExplodingExploit,
        fake_red_agents["VerificationAgent"],
    )

    graph = sup.create_red_team_graph()
    final = graph.invoke(_initial_state())

    # Terminated straight after recon: exploitation_node never advanced the phase
    # or step_count past recon (ExplodingExploit would have raised otherwise).
    # As with the hard-cap path, _terminate()'s outcome/failure_reason writes live
    # in the edge function and are not persisted, so we assert on the persisted
    # node-written state instead.
    assert final["phase"] == AttackPhase.RECON
    assert final["step_count"] == 1
    assert final["recon_summary"]["ports"] == []
    assert final.get("outcome") != AttackOutcome.SUCCESS
