# =============================================================================
# agents/red_team/supervisor.py
# OWNER: Red Team Hire
# PURPOSE: LangGraph Supervisor Node — central router for the Red Team pipeline.
#          Enforces hard caps, validates plans, routes between agents.
# =============================================================================
#
# TODO (Red Team Hire): Implement the LangGraph state machine.
#
# REQUIRED BEHAVIORS (enforced here — not in the LLM):
#   ✗ Reject exploitation plans targeting services not found in recon
#   ✗ Reject plans after 3 retries — mark as FAILED
#   ✗ Force termination at 30 steps / 50K tokens / 15 minutes
#   ✓ Log every routing decision to state.supervisor_notes
#   ✓ Evaluator gate: lightweight sanity check before routing to exploitation
#
# REFERENCE: Red Team Report — Section 4.2.1 and 4.3
# =============================================================================

import uuid
import time
from langgraph.graph import StateGraph, END
from loguru import logger

from agents.red_team.state import RedTeamState, AttackPhase, AttackOutcome
from agents.shared.ollama_client import get_client

# Hard caps — DO NOT change without lead approval
MAX_STEPS   = 30
MAX_TOKENS  = 50_000
MAX_SECONDS = 900   # 15 minutes
MAX_RETRIES = 3


def create_red_team_graph() -> StateGraph:
    """
    Builds and returns the Red Team LangGraph state machine.

    TODO: Implement the following nodes and edges:
        Nodes:  init_node, recon_node, exploitation_node, verification_node
        Edges:  conditional routing based on state after each node
        Entry:  init_node
    """
    # TODO (Red Team Hire): implement full graph
    graph = StateGraph(RedTeamState)
    raise NotImplementedError("Red Team graph not yet implemented — see TODO above")


def supervisor_route(state: RedTeamState) -> str:
    """
    Routing logic called by LangGraph after each node.
    Returns the name of the next node to execute, or END.

    This function enforces all hard caps before any other routing logic.
    """
    # --- Hard cap checks (always run first) ---
    if state["step_count"] >= MAX_STEPS:
        logger.warning(f"[red/supervisor] Hard cap: max steps ({MAX_STEPS}) reached")
        return _terminate(state, AttackOutcome.TIMEOUT, f"Max steps ({MAX_STEPS}) reached")

    if state["token_count"] >= MAX_TOKENS:
        logger.warning(f"[red/supervisor] Hard cap: token budget ({MAX_TOKENS}) exhausted")
        return _terminate(state, AttackOutcome.TIMEOUT, "Token budget exhausted")

    if state["retry_count"] >= MAX_RETRIES:
        logger.warning(f"[red/supervisor] Hard cap: max retries ({MAX_RETRIES}) reached")
        return _terminate(state, AttackOutcome.FAILURE, f"Max retries ({MAX_RETRIES}) reached")

    # --- Phase routing ---
    phase = state["phase"]

    if phase == AttackPhase.INIT:
        return "recon_node"

    if phase == AttackPhase.RECON:
        if not state.get("recon_summary") or not state["recon_summary"].get("ports"):
            logger.warning("[red/supervisor] Recon returned no services — terminating")
            return _terminate(state, AttackOutcome.FAILURE, "No services found in recon")
        return "exploitation_node"

    if phase == AttackPhase.EXPLOITATION:
        if state.get("grader_confirmed"):
            return "verification_node"
        # Plan validation: reject if targeting undiscovered services
        if not _validate_attack_plan(state):
            return "exploitation_node"   # retry with updated memory
        return "exploitation_node"

    if phase == AttackPhase.VERIFICATION:
        return END

    if phase in (AttackPhase.COMPLETE, AttackPhase.FAILED):
        return END

    return END


def _terminate(state: RedTeamState, outcome: AttackOutcome, reason: str) -> str:
    """Marks the engagement as terminated and returns END."""
    state["outcome"]       = outcome
    state["failure_reason"] = reason
    state["phase"]         = AttackPhase.FAILED if outcome != AttackOutcome.SUCCESS else AttackPhase.COMPLETE
    state["supervisor_notes"].append(f"TERMINATED: {reason}")
    return END


def _validate_attack_plan(state: RedTeamState) -> bool:
    """
    Evaluator gate: rejects exploitation plans that target services
    not discovered during recon.

    Returns True if the plan is valid, False if it should be rejected.
    """
    plan = state.get("attack_plan")
    if not plan:
        return False

    discovered_services = {
        p.get("service", "").lower()
        for p in state.get("recon_summary", {}).get("ports", [])
    }

    target_service = plan.get("target_service", "").lower()
    if target_service and target_service not in discovered_services:
        logger.warning(
            f"[red/supervisor] Plan rejected: targets '{target_service}' "
            f"not in discovered services {discovered_services}"
        )
        state["supervisor_notes"].append(
            f"Plan rejected: '{target_service}' not in recon output"
        )
        state["retry_count"] += 1
        return False

    return True