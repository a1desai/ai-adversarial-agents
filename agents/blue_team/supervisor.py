# =============================================================================
# agents/blue_team/supervisor.py
# OWNER: Blue Team Hire
# PURPOSE: LangGraph Supervisor Node — central router for the Blue Team pipeline.
#          Enforces hard caps, validates outputs, routes between agents.
# =============================================================================
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

import time
import uuid

from langgraph.graph import END, StateGraph
from loguru import logger

from agents.blue_team.blue_team import BlueTeamState, DefensePhase, PatchOutcome
from agents.blue_team.log_analysis_agent import LogAnalysisAgent
from agents.blue_team.patch_generation_agent import PatchGenerationAgent
from agents.blue_team.patch_validation_agent import PatchValidationAgent
from agents.blue_team.root_cause_agent import RootCauseAgent
from agents.shared.mcp_transport import BlueTeamTransport
from evaluation.trace_logger import TraceLogger

# Hard caps — DO NOT change without lead approval (must match Red Team caps)
MAX_STEPS = 30
MAX_TOKENS = 50_000
MAX_SECONDS = 900  # 15 minutes
MAX_PATCH_ATTEMPTS = 3
MIN_CONFIDENCE_DEPLOY = 0.6  # below this, regenerate instead of deploying


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------


def init_node(state: BlueTeamState) -> BlueTeamState:
    """Sets up a fresh engagement: trace ID, counters, initial phase."""
    state["trace_id"] = str(uuid.uuid4())
    state["phase"] = DefensePhase.INIT
    state["step_count"] = 0
    state["token_count"] = 0
    state["patch_attempt_count"] = 0
    state["elapsed_seconds"] = 0.0
    state["supervisor_notes"] = []
    state["_started_monotonic"] = time.monotonic()
    logger.info(
        f"[blue/init] Engagement started trace_id={state['trace_id']} "
        f"cve={state.get('target_cve')} container={state.get('container_id')}"
    )
    return state


def log_analysis_node(state: BlueTeamState) -> BlueTeamState:
    """Runs LogAnalysisAgent and stores the Attack Summary in state."""
    logger.info(f"[blue/log_analysis] Reconstructing attack on {state['container_id']}")
    agent = LogAnalysisAgent()
    summary = agent.analyze(
        container_id=state["container_id"],
        exploit_timestamp=state["exploit_timestamp"],
    )
    state["attack_summary"] = summary
    state["phase"] = DefensePhase.LOG_ANALYSIS
    state["step_count"] += 1
    _update_elapsed(state)
    state["supervisor_notes"].append(
        f"Log analysis complete: endpoint={summary.get('target_endpoint')} "
        f"confidence={summary.get('confidence')}"
    )
    _log_trace(
        state, "log_analysis_agent", "analyze", {"container_id": state["container_id"]}, summary
    )
    return state


def root_cause_node(state: BlueTeamState) -> BlueTeamState:
    """Runs RootCauseAgent and stores the Vulnerability Analysis in state."""
    logger.info("[blue/root_cause] Identifying vulnerable code path")
    agent = RootCauseAgent()
    analysis = agent.analyze(
        attack_summary=state["attack_summary"],
        container_id=state["container_id"],
    )
    state["vulnerability_analysis"] = analysis
    state["phase"] = DefensePhase.ROOT_CAUSE
    state["step_count"] += 1
    _update_elapsed(state)
    state["supervisor_notes"].append(
        f"Root cause: {analysis.get('cwe_classification')} "
        f"confidence={analysis.get('confidence')}"
    )
    _log_trace(state, "root_cause_agent", "analyze", state["attack_summary"], analysis)
    return state


def patch_generation_node(state: BlueTeamState) -> BlueTeamState:
    """Reads the vulnerable source file and runs PatchGenerationAgent."""
    vulnerability_analysis = state["vulnerability_analysis"]
    attempt_number = state["patch_attempt_count"] + 1
    logger.info(f"[blue/patch_generation] Generating patch (attempt {attempt_number})")

    transport = BlueTeamTransport()
    source_result = transport.read_source_file(
        state["container_id"], vulnerability_analysis["vulnerable_file"]
    )

    agent = PatchGenerationAgent()
    patch = agent.generate_patch(
        vulnerability_analysis=vulnerability_analysis,
        source_code=source_result.raw_output,
        attempt_number=attempt_number,
    )

    state["patch_diff"] = patch.get("patch_diff")
    state["patch_confidence"] = patch.get("confidence")
    state["patch_strategy"] = patch.get("strategy_used")
    state["phase"] = DefensePhase.PATCH_GENERATION
    state["step_count"] += 1
    _update_elapsed(state)
    state["supervisor_notes"].append(
        f"Patch generated (attempt {attempt_number}): "
        f"strategy={patch.get('strategy_used')} confidence={patch.get('confidence')}"
    )
    _log_trace(state, "patch_generation_agent", "generate_patch", vulnerability_analysis, patch)
    return state


def patch_validation_node(state: BlueTeamState) -> BlueTeamState:
    """Runs PatchValidationAgent, then logs the attempt to blue episodic memory."""
    logger.info("[blue/patch_validation] Validating patch")
    agent = PatchValidationAgent()
    vulnerability_analysis = state["vulnerability_analysis"]

    result = agent.validate(
        container_id=state["container_id"],
        patch_diff=state["patch_diff"],
        allowed_patch_paths=vulnerability_analysis.get("allowed_patch_paths", []),
        functional_health_url=state["functional_health_url"],
        exploit_replay_trace=state["exploit_replay_trace"],
    )

    state["patch_applies_cleanly"] = result.get("patch_applies_cleanly", False)
    state["functional_tests_passed"] = result.get("functional_tests_passed", False)
    state["exploit_blocked"] = result.get("exploit_blocked", False)
    state["regression_introduced"] = result.get("regression_introduced", False)
    state["phase"] = DefensePhase.PATCH_VALIDATION
    state["step_count"] += 1
    _update_elapsed(state)
    state["supervisor_notes"].append(
        f"Validation: applies_cleanly={state['patch_applies_cleanly']} "
        f"functional={state['functional_tests_passed']} "
        f"exploit_blocked={state['exploit_blocked']} "
        f"regression={state['regression_introduced']}"
    )
    _log_trace(state, "patch_validation_agent", "validate", vulnerability_analysis, result)

    _log_patch_episode(state)
    return state


def finalize_node(state: BlueTeamState) -> BlueTeamState:
    """Sets the final outcome based on validation results. Must be a proper node so
    LangGraph persists the state writes."""
    if state.get("exploit_blocked") and state.get("functional_tests_passed"):
        state["outcome"] = PatchOutcome.SUCCESS
        state["phase"] = DefensePhase.COMPLETE
    elif state.get("regression_introduced"):
        state["outcome"] = PatchOutcome.REGRESSION
        state["failure_reason"] = "Patch introduced a regression"
        state["phase"] = DefensePhase.FAILED
    else:
        state["outcome"] = PatchOutcome.FAILURE
        state["failure_reason"] = "Max patch attempts reached without a confirmed fix"
        state["phase"] = DefensePhase.FAILED
    logger.info(f"[blue/finalize] outcome={state['outcome']} phase={state['phase']}")
    return state


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def create_blue_team_graph():
    """
    Builds and compiles the Blue Team LangGraph state machine.

    Flow: init_node -> log_analysis_node -> root_cause_node ->
          patch_generation_node -> patch_validation_node -> finalize_node
    supervisor_route() enforces hard caps and routes between phases.
    finalize_node() writes the final outcome (must be a node, not a conditional edge).
    """
    graph = StateGraph(BlueTeamState)

    graph.add_node("init_node", init_node)
    graph.add_node("log_analysis_node", log_analysis_node)
    graph.add_node("root_cause_node", root_cause_node)
    graph.add_node("patch_generation_node", patch_generation_node)
    graph.add_node("patch_validation_node", patch_validation_node)
    graph.add_node("finalize_node", finalize_node)

    graph.set_entry_point("init_node")

    graph.add_conditional_edges("init_node", supervisor_route)
    graph.add_conditional_edges("log_analysis_node", supervisor_route)
    graph.add_conditional_edges("root_cause_node", supervisor_route)
    graph.add_conditional_edges("patch_generation_node", supervisor_route)
    graph.add_conditional_edges("patch_validation_node", supervisor_route)
    graph.add_edge("finalize_node", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Routing logic (conditional edge function)
# ---------------------------------------------------------------------------


def supervisor_route(state: BlueTeamState) -> str:
    """
    Routing logic called by LangGraph after each node.
    Returns the name of the next node to execute, or END.

    This function enforces all hard caps before any other routing logic.
    """
    # --- Hard cap checks (always run first) ---
    if state["step_count"] >= MAX_STEPS:
        logger.warning(f"[blue/supervisor] Hard cap: max steps ({MAX_STEPS}) reached")
        return _terminate(state, PatchOutcome.TIMEOUT, f"Max steps ({MAX_STEPS}) reached")

    if state["token_count"] >= MAX_TOKENS:
        logger.warning(f"[blue/supervisor] Hard cap: token budget ({MAX_TOKENS}) exhausted")
        return _terminate(state, PatchOutcome.TIMEOUT, "Token budget exhausted")

    if state.get("elapsed_seconds", 0.0) >= MAX_SECONDS:
        logger.warning(f"[blue/supervisor] Hard cap: max seconds ({MAX_SECONDS}) reached")
        return _terminate(state, PatchOutcome.TIMEOUT, f"Max seconds ({MAX_SECONDS}) reached")

    if state["patch_attempt_count"] >= MAX_PATCH_ATTEMPTS:
        logger.warning(
            f"[blue/supervisor] Hard cap: max patch attempts ({MAX_PATCH_ATTEMPTS}) reached"
        )
        return _terminate(
            state, PatchOutcome.FAILURE, f"Max patch attempts ({MAX_PATCH_ATTEMPTS}) reached"
        )

    # --- Phase routing ---
    phase = state["phase"]

    if phase == DefensePhase.INIT:
        return "log_analysis_node"

    if phase == DefensePhase.LOG_ANALYSIS:
        if not state.get("attack_summary"):
            logger.warning("[blue/supervisor] Log analysis produced no attack summary")
            return _terminate(
                state, PatchOutcome.FAILURE, "Log analysis produced no attack summary"
            )
        return "root_cause_node"

    if phase == DefensePhase.ROOT_CAUSE:
        analysis = state.get("vulnerability_analysis")
        if not analysis or not analysis.get("allowed_patch_paths"):
            logger.warning("[blue/supervisor] Root cause analysis produced no allowed_patch_paths")
            return _terminate(
                state, PatchOutcome.FAILURE, "Root cause analysis produced no allowed_patch_paths"
            )
        return "patch_generation_node"

    if phase == DefensePhase.PATCH_GENERATION:
        # Confidence gate: below MIN_CONFIDENCE_DEPLOY, regenerate rather than deploy.
        confidence = state.get("patch_confidence")
        if confidence is None or confidence < MIN_CONFIDENCE_DEPLOY:
            logger.warning(
                f"[blue/supervisor] Patch confidence {confidence} below "
                f"{MIN_CONFIDENCE_DEPLOY} — regenerating"
            )
            state["patch_attempt_count"] += 1
            state["supervisor_notes"].append(
                f"Patch rejected: confidence {confidence} below {MIN_CONFIDENCE_DEPLOY}"
            )
            return "patch_generation_node"
        return "patch_validation_node"

    if phase == DefensePhase.PATCH_VALIDATION:
        # Completion gate: both security AND functional checks must pass.
        if state.get("exploit_blocked") and state.get("functional_tests_passed"):
            return "finalize_node"

        # Validation failed — retry with another patch generation attempt
        # (the hard cap above already stops this once MAX_PATCH_ATTEMPTS is hit).
        state["patch_attempt_count"] += 1
        state["supervisor_notes"].append(
            "Patch rejected: validation failed — "
            f"functional={state.get('functional_tests_passed')} "
            f"exploit_blocked={state.get('exploit_blocked')}"
        )
        return "patch_generation_node"

    if phase in (DefensePhase.COMPLETE, DefensePhase.FAILED):
        return END

    return END


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _terminate(state: BlueTeamState, outcome: PatchOutcome, reason: str) -> str:
    """Marks the engagement as terminated and returns END."""
    state["outcome"] = outcome
    state["failure_reason"] = reason
    state["phase"] = (
        DefensePhase.FAILED if outcome != PatchOutcome.SUCCESS else DefensePhase.COMPLETE
    )
    state["supervisor_notes"].append(f"TERMINATED: {reason}")
    return END


def _update_elapsed(state: BlueTeamState) -> None:
    """Refreshes elapsed_seconds from the monotonic start time set in init_node."""
    started = state.get("_started_monotonic")
    if started is not None:
        state["elapsed_seconds"] = time.monotonic() - started


def _log_patch_episode(state: BlueTeamState) -> None:
    """Logs this patch attempt to blue episodic memory via PatchGenerationAgent._log_episode()."""
    if state.get("exploit_blocked") and state.get("functional_tests_passed"):
        outcome = PatchOutcome.SUCCESS
    elif state.get("regression_introduced"):
        outcome = PatchOutcome.REGRESSION
    else:
        outcome = PatchOutcome.FAILURE

    vulnerability_analysis = state.get("vulnerability_analysis") or {}
    try:
        PatchGenerationAgent()._log_episode(
            target_cve=state.get("target_cve", ""),
            cwe_classification=vulnerability_analysis.get("cwe_classification", ""),
            patch_strategy=state.get("patch_strategy") or "",
            patch_diff=state.get("patch_diff") or "",
            outcome=outcome.value,
            failure_reason=state.get("failure_reason"),
        )
    except Exception as exc:
        logger.warning(f"[blue/supervisor] Episode log failed: {exc}")


def _log_trace(
    state: BlueTeamState,
    agent: str,
    action: str,
    input_data: dict,
    output_data: dict,
) -> None:
    """Logs one agent step to the engagement trace file."""
    try:
        tracer = TraceLogger(team="blue", target_cve=state.get("target_cve") or "unknown")
        tracer.log(agent, action, input_data, output_data, tokens_used=0)
    except Exception as exc:
        # Trace failure must never crash the pipeline
        logger.warning(f"[blue/supervisor] Trace log failed: {exc}")
