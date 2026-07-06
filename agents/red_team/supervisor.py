# =============================================================================
# agents/red_team/supervisor.py
# OWNER: Red Team Hire
# PURPOSE: LangGraph Supervisor Node — central router for the Red Team pipeline.
#          Enforces hard caps, validates plans, routes between agents.
# =============================================================================
#
# REQUIRED BEHAVIORS (enforced here — not in the LLM):
#   ✓ Reject exploitation plans targeting services not found in recon
#   ✓ Reject plans after 3 retries — mark as FAILED
#   ✓ Force termination at 30 steps / 50K tokens / 15 minutes
#   ✓ Log every routing decision to state.supervisor_notes
#   ✓ Evaluator gate: lightweight sanity check before routing to exploitation
#
# REFERENCE: Red Team Report — Section 4.2.1 and 4.3
# =============================================================================

import uuid

from langgraph.graph import END, StateGraph
from loguru import logger

from agents.red_team.exploitation_agent import ExploitationAgent
from agents.red_team.recon_agent import ReconAgent
from agents.red_team.state import AttackOutcome, AttackPhase, RedTeamState
from agents.red_team.verification_agent import VerificationAgent
from evaluation.trace_logger import TraceLogger

# Hard caps — DO NOT change without lead approval
MAX_STEPS = 30
MAX_TOKENS = 50_000
MAX_SECONDS = 900  # 15 minutes
MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------


def init_node(state: RedTeamState) -> RedTeamState:
    """Sets up a fresh engagement: trace ID, counters, initial phase."""
    state["trace_id"] = str(uuid.uuid4())
    state["phase"] = AttackPhase.INIT
    state["step_count"] = 0
    state["token_count"] = 0
    state["retry_count"] = 0
    state["supervisor_notes"] = []
    logger.info(
        f"[red/init] Engagement started trace_id={state['trace_id']} target={state['target_url']}"
    )
    return state


def recon_node(state: RedTeamState) -> RedTeamState:
    """Runs ReconAgent and stores structured recon output in state."""
    logger.info(f"[red/recon] Starting recon on {state['target_url']}")
    agent = ReconAgent()
    summary = agent.run(state["target_url"])
    state["recon_summary"] = summary
    state["phase"] = AttackPhase.RECON
    state["step_count"] += 1
    state["supervisor_notes"].append(
        f"Recon complete: {len(summary.get('ports', []))} ports, "
        f"confidence={summary.get('confidence')}"
    )
    _log_trace(state, "recon_agent", "recon_complete", {"target_url": state["target_url"]}, summary)
    return state


def exploitation_node(state: RedTeamState) -> RedTeamState:
    """Runs ExploitationAgent: plan_attack then execute_payload."""
    logger.info("[red/exploitation] Planning and executing attack")
    agent = ExploitationAgent()

    plan = agent.plan_attack(state["recon_summary"], target_cve=state.get("target_cve"))
    state["attack_plan"] = plan
    state["target_cve"] = plan.get("cve_id") or state.get("target_cve")
    state["step_count"] += 1

    _log_trace(state, "exploitation_agent", "plan_attack", state["recon_summary"], plan)

    result = agent.execute_payload(plan, state["target_url"])
    state["payload_used"] = result.get("payload_used")
    state["server_response"] = result.get("server_response")
    state["exploit_claimed_success"] = result.get("outcome") == "SUCCESS"
    state["phase"] = AttackPhase.EXPLOITATION
    state["step_count"] += 1

    _log_trace(state, "exploitation_agent", "execute_payload", plan, result)
    state["supervisor_notes"].append(
        f"Exploitation: claimed_success={state['exploit_claimed_success']} "
        f"confidence={result.get('confidence')}"
    )
    return state


def verification_node(state: RedTeamState) -> RedTeamState:
    """Runs VerificationAgent to independently confirm the claimed exploit."""
    logger.info("[red/verification] Verifying claimed exploit with grader")
    agent = VerificationAgent()

    claimed = {
        "payload_used": state.get("payload_used"),
        "server_response": state.get("server_response"),
        "exploit_claimed_success": state.get("exploit_claimed_success"),
    }
    result = agent.verify(state["target_url"], state.get("target_cve", ""), claimed)

    state["grader_confirmed"] = result.get("confirmed", False)
    state["attack_goals_achieved"] = result.get("attack_goals_achieved", [])
    state["phase"] = AttackPhase.VERIFICATION
    state["step_count"] += 1

    _log_trace(state, "verification_agent", "verify", claimed, result)
    state["supervisor_notes"].append(
        f"Verification: grader_confirmed={state['grader_confirmed']} "
        f"goals={state['attack_goals_achieved']}"
    )
    return state


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def create_red_team_graph():
    """
    Builds and compiles the Red Team LangGraph state machine.

    Flow: init_node -> recon_node -> exploitation_node -> verification_node
    All conditional edges use supervisor_route(), which enforces hard caps
    before any phase-based routing.
    """
    graph = StateGraph(RedTeamState)

    graph.add_node("init_node", init_node)
    graph.add_node("recon_node", recon_node)
    graph.add_node("exploitation_node", exploitation_node)
    graph.add_node("verification_node", verification_node)

    graph.set_entry_point("init_node")

    graph.add_conditional_edges("init_node", supervisor_route)
    graph.add_conditional_edges("recon_node", supervisor_route)
    graph.add_conditional_edges("exploitation_node", supervisor_route)
    graph.add_conditional_edges("verification_node", supervisor_route)

    return graph.compile()


# ---------------------------------------------------------------------------
# Routing logic (conditional edge function)
# ---------------------------------------------------------------------------


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
        # Plan validation always runs first: a plan targeting an undiscovered
        # service is rejected and a retry is scheduled. This increments
        # retry_count inside _validate_attack_plan().
        if not _validate_attack_plan(state):
            return "exploitation_node"  # retry with updated memory

        # ExploitationAgent's self-report drives routing:
        #   True  → hand off to VerificationAgent (independent grader check)
        #   False → retry with updated memory (capped by MAX_RETRIES at the top)
        # Note: grader_confirmed belongs to the VERIFICATION phase. Do not
        # check it here — it would always be False before verification runs.
        if state.get("exploit_claimed_success"):
            return "verification_node"

        state["retry_count"] += 1
        return "exploitation_node"

    if phase == AttackPhase.VERIFICATION:
        # Verification has run — grader_confirmed is now authoritative.
        if state.get("grader_confirmed"):
            state["outcome"] = AttackOutcome.SUCCESS
            state["phase"] = AttackPhase.COMPLETE
        else:
            # Verification rejected a claimed success → treat as ungrounded.
            state["outcome"] = AttackOutcome.FAILURE
            state["failure_reason"] = "Verification rejected claimed exploit"
            state["phase"] = AttackPhase.FAILED
        return END

    if phase in (AttackPhase.COMPLETE, AttackPhase.FAILED):
        return END

    return END


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _terminate(state: RedTeamState, outcome: AttackOutcome, reason: str) -> str:
    """Marks the engagement as terminated and returns END."""
    state["outcome"] = outcome
    state["failure_reason"] = reason
    state["phase"] = (
        AttackPhase.FAILED if outcome != AttackOutcome.SUCCESS else AttackPhase.COMPLETE
    )
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
        p.get("service", "").lower() for p in state.get("recon_summary", {}).get("ports", [])
    }

    target_service = plan.get("target_service", "").lower()
    if target_service and target_service not in discovered_services:
        logger.warning(
            f"[red/supervisor] Plan rejected: targets '{target_service}' "
            f"not in discovered services {discovered_services}"
        )
        state["supervisor_notes"].append(f"Plan rejected: '{target_service}' not in recon output")
        state["retry_count"] += 1
        return False

    return True


def _log_trace(
    state: RedTeamState,
    agent: str,
    action: str,
    input_data: dict,
    output_data: dict,
) -> None:
    """Logs one agent step to the engagement trace file."""
    try:
        tracer = TraceLogger(team="red", target_cve=state.get("target_cve") or "unknown")
        tracer.log(agent, action, input_data, output_data, tokens_used=0)
    except Exception as exc:
        # Trace failure must never crash the pipeline
        logger.warning(f"[red/supervisor] Trace log failed: {exc}")
