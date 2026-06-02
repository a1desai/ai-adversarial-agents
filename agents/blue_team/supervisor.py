# =============================================================================
# agents/blue_team/supervisor.py
# OWNER: Blue Team Hire
# PURPOSE: LangGraph Supervisor Node — central router for the Blue Team pipeline.
#          Enforces hard caps, validates outputs, routes between agents.
# =============================================================================
#
# TODO (Blue Team Hire): Implement the LangGraph state machine.
#
# REQUIRED BEHAVIORS (enforced here — not in the LLM):
#   ✗ Reject patches that touch files outside vulnerability_analysis.allowed_patch_paths
#     (mcp_transport already enforces this — supervisor must also gate before deploy)
#   ✗ Reject patches with confidence < 0.6 — request regeneration with retrieval
#   ✗ Reject patches that fail functional health checks
#   ✗ Force termination at 30 steps / 50K tokens / 15 minutes
#   ✓ Max 3 patch attempts per vulnerability — supervisor enforces this counter
#   ✓ Log every routing decision to state.supervisor_notes
#
# REFERENCE: Blue Team Report — Section 4.2.1 and 4.3
# =============================================================================

from langgraph.graph import StateGraph

from agents.blue_team.blue_team import BlueTeamState

# Hard caps — DO NOT change without lead approval (must match Red Team caps)
MAX_STEPS = 30
MAX_TOKENS = 50_000
MAX_SECONDS = 900  # 15 minutes
MAX_PATCH_ATTEMPTS = 3
MIN_CONFIDENCE_DEPLOY = 0.6  # below this, regenerate instead of deploying


def create_blue_team_graph() -> StateGraph:
    """
    Builds and returns the Blue Team LangGraph state machine.

    TODO: Implement the following nodes and edges:
        Nodes:  init_node, log_analysis_node, root_cause_node,
                patch_generation_node, patch_validation_node
        Edges:  conditional routing based on state after each node
        Entry:  init_node (triggered by hypervisor exploit_detected event)
    """
    # TODO (Blue Team Hire): implement full graph
    raise NotImplementedError("Blue Team graph not yet implemented — see TODO above")


def supervisor_route(state: BlueTeamState) -> str:
    """
    Routing logic called by LangGraph after each node.
    Returns the name of the next node to execute, or END.

    This function enforces all hard caps before any other routing logic.
    """
    # TODO (Blue Team Hire): implement full routing
    # Order of checks (do not change):
    #   1. Hard caps (steps, tokens, seconds) → terminate
    #   2. Patch attempt cap (3) → terminate as FAILURE
    #   3. Phase-based routing (init → log_analysis → root_cause → patch_gen → patch_val)
    #   4. Confidence gate: patch_confidence < 0.6 → route back to patch_generation
    #   5. Validation gate: exploit_blocked AND functional_tests_passed → COMPLETE
    raise NotImplementedError("Blue Team supervisor_route() not yet implemented")
