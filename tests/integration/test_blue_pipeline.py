# =============================================================================
# tests/integration/test_blue_pipeline.py
# OWNER: Evaluation / KB Hire
# MARKERS: integration (no Ollama, Docker or network — every agent is mocked)
# PURPOSE: End-to-end integration tests for the Blue Team pipeline. Drives
#          create_blue_team_graph() from a simulated hypervisor
#          exploit_detected event through log analysis -> root cause ->
#          patch generation -> patch validation -> finalize, and asserts the
#          supervisor's four required gates: success, confidence < 0.6,
#          allowed_patch_paths scope, and the 3-attempt cap.
# RUN: pytest tests/integration/test_blue_pipeline.py -m integration -v
# REFERENCE: Blue Team Report — Section 4.2.1 / 4.3 (supervisor gates);
#            docs/issues.md #70
# =============================================================================
# NOTE: AI-assisted (drafted with Claude), human-reviewed.

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from langgraph.graph import END

from agents.blue_team.blue_team import DefensePhase, PatchOutcome
from agents.blue_team.supervisor import (
    MAX_PATCH_ATTEMPTS,
    MAX_STEPS,
    MIN_CONFIDENCE_DEPLOY,
    create_blue_team_graph,
    finalize_node,
    patch_validation_node,
    supervisor_route,
)
from agents.shared.mcp_transport import BlueTeamTransport
from hypervisor.event_emitter import EXPLOIT_DETECTED, EventEmitter, ExploitDetectedEvent

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixed agent payloads — the shapes each Blue Team agent really returns
# ---------------------------------------------------------------------------

CONTAINER_ID = "blue-target-wordpress-1"
TARGET_URL = "http://target-wordpress:80"
HEALTH_URL = "http://target-wordpress:80/health"
REPLAY_TRACE = "red-trace-0001"
VULNERABLE_FILE = "wp-includes/class-wpdb.php"

ATTACK_SUMMARY = {
    "target_endpoint": "/wp-admin/admin-ajax.php",
    "payload_observed": "id=1' UNION SELECT user_pass FROM wp_users--",
    "attack_goal_achieved": "database_access",
    "http_status_sequence": [200, 500, 200],
    "evidence_excerpts": ["GET /wp-admin/admin-ajax.php?id=1' UNION SELECT ... HTTP/1.1 200"],
    "confidence": 0.91,
}

VULNERABILITY_ANALYSIS = {
    "cwe_classification": "CWE-89: SQL Injection",
    "vulnerable_file": VULNERABLE_FILE,
    "vulnerable_function": "query",
    "vulnerable_line": 142,
    "missing_control": "No input sanitization before SQL query",
    "allowed_patch_paths": [VULNERABLE_FILE],
    "evidence": "raw string concatenation of $id into the SQL statement",
    "confidence": 0.87,
}

IN_SCOPE_DIFF = (
    f"--- a/{VULNERABLE_FILE}\n"
    f"+++ b/{VULNERABLE_FILE}\n"
    "@@ -142,1 +142,1 @@\n"
    '-$sql = "SELECT * FROM wp_users WHERE id = " . $id;\n'
    '+$sql = $wpdb->prepare("SELECT * FROM wp_users WHERE id = %d", $id);\n'
)

OUT_OF_SCOPE_DIFF = (
    "--- a/wp-config.php\n"
    "+++ b/wp-config.php\n"
    "@@ -1,1 +1,1 @@\n"
    "-define('DB_USER', 'wp');\n"
    "+define('DB_USER', 'readonly');\n"
)

TRAVERSAL_DIFF = "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1,1 +1,1 @@\n-root\n+root\n"

HIGH_CONFIDENCE_PATCH = {
    "patch_diff": IN_SCOPE_DIFF,
    "confidence": 0.9,
    "strategy_used": "applied $wpdb->prepare() parameterization",
    "rationale": "CWE-89 in PHP requires prepared statements, not escaping",
}

LOW_CONFIDENCE_PATCH = {
    "patch_diff": IN_SCOPE_DIFF,
    "confidence": 0.4,
    "strategy_used": "regex-filtered the id parameter",
    "rationale": "Filtering is a weak control — low confidence",
}

OUT_OF_SCOPE_PATCH = {
    "patch_diff": OUT_OF_SCOPE_DIFF,
    "confidence": 0.88,
    "strategy_used": "downgraded the database user in wp-config.php",
    "rationale": "Least privilege — but touches a file outside the analysis",
}

VALIDATION_SUCCESS = {
    "patch_applies_cleanly": True,
    "functional_tests_passed": True,
    "exploit_blocked": True,
    "regression_introduced": False,
    "details": "Health check -> HTTP 200 | Replay returned HTTP 400, no indicators matched",
}

VALIDATION_EXPLOIT_STILL_WORKS = {
    "patch_applies_cleanly": True,
    "functional_tests_passed": True,
    "exploit_blocked": False,
    "regression_introduced": False,
    "details": "Replay still matched success indicators: ['wp_users']",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _state_from_event(event: ExploitDetectedEvent) -> dict:
    """
    Builds the BlueTeamState the supervisor is handed when the hypervisor
    confirms an exploit. Only the trigger fields are populated — every other
    field is filled in by the pipeline itself.
    """
    assert event.event == EXPLOIT_DETECTED
    return {
        "target_cve": event.cve_id,
        "target_url": TARGET_URL,
        "container_id": CONTAINER_ID,
        "exploit_timestamp": event.timestamp,
        "functional_health_url": HEALTH_URL,
        "exploit_replay_trace": REPLAY_TRACE,
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


def _scope_checked_validation(**kwargs) -> dict:
    """
    Stand-in for PatchValidationAgent.validate() that runs the REAL
    allowed_patch_paths whitelist (BlueTeamTransport._validate_patch_scope) —
    no Docker involved, because a scope violation short-circuits deploy_patch
    before any subprocess runs.
    """
    violation = BlueTeamTransport()._validate_patch_scope(
        kwargs["patch_diff"], kwargs["allowed_patch_paths"]
    )
    if violation:
        return {
            "patch_applies_cleanly": False,
            "functional_tests_passed": False,
            "exploit_blocked": False,
            "regression_introduced": False,
            "details": f"Patch scope violation: {violation}",
        }
    return VALIDATION_SUCCESS


@contextmanager
def mocked_blue_agents(patch_results: list[dict], validate):
    """
    Patches every Ollama/Docker-backed dependency the supervisor reaches for,
    so the graph runs fully offline.

    Args:
        patch_results: one dict per PatchGenerationAgent.generate_patch() call
        validate:      a list of validation dicts, or a callable side effect

    Yields:
        A MagicMock namespace with .log_analysis/.root_cause/.patch_gen/
        .patch_validation/.transport and .call_order (node call sequence).
    """
    ns = MagicMock()
    ns.call_order = []

    with (
        patch("agents.blue_team.supervisor.TraceLogger") as tracer,
        patch("agents.blue_team.supervisor.BlueTeamTransport") as transport_cls,
        patch("agents.blue_team.supervisor.LogAnalysisAgent") as log_cls,
        patch("agents.blue_team.supervisor.RootCauseAgent") as root_cls,
        patch("agents.blue_team.supervisor.PatchGenerationAgent") as gen_cls,
        patch("agents.blue_team.supervisor.PatchValidationAgent") as val_cls,
    ):
        transport_cls.return_value.read_source_file.return_value = MagicMock(
            raw_output="<?php $sql = 'SELECT * FROM wp_users WHERE id = ' . $id; ?>",
            success=True,
        )

        def _analyze_logs(**kwargs):
            ns.call_order.append("log_analysis")
            return ATTACK_SUMMARY

        def _analyze_root_cause(**kwargs):
            ns.call_order.append("root_cause")
            return VULNERABILITY_ANALYSIS

        results = list(patch_results)

        def _generate_patch(**kwargs):
            ns.call_order.append("patch_generation")
            return results.pop(0) if len(results) > 1 else results[0]

        if callable(validate):

            def _validate(**kwargs):
                ns.call_order.append("patch_validation")
                return validate(**kwargs)

        else:
            validations = list(validate)

            def _validate(**kwargs):
                ns.call_order.append("patch_validation")
                return validations.pop(0) if len(validations) > 1 else validations[0]

        log_cls.return_value.analyze.side_effect = _analyze_logs
        root_cls.return_value.analyze.side_effect = _analyze_root_cause
        gen_cls.return_value.generate_patch.side_effect = _generate_patch
        val_cls.return_value.validate.side_effect = _validate

        ns.tracer = tracer
        ns.transport = transport_cls
        ns.log_analysis = log_cls.return_value.analyze
        ns.root_cause = root_cls.return_value.analyze
        ns.patch_gen = gen_cls.return_value.generate_patch
        ns.patch_validation = val_cls.return_value.validate
        ns.episode_log = gen_cls.return_value._log_episode

        yield ns


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def exploit_event(tmp_path) -> ExploitDetectedEvent:
    """
    Emits a real hypervisor exploit_detected event onto an isolated stream and
    returns it. This is the only thing that may activate the Blue Team.
    """
    received: list[ExploitDetectedEvent] = []
    emitter = EventEmitter(event_stream=tmp_path / "events.jsonl")
    emitter.subscribe(received.append)

    event = emitter.emit_exploit_detected(
        cve_id="CVE-2024-31210",
        target_endpoint="/wp-admin/admin-ajax.php",
        attack_goal_achieved="database_access",
    )
    assert received == [event], "Blue Team never received the exploit_detected event"
    return event


@pytest.fixture
def blue_graph():
    return create_blue_team_graph()


# ---------------------------------------------------------------------------
# Happy path: exploit_detected -> ... -> PatchOutcome.SUCCESS
# ---------------------------------------------------------------------------


class TestBlueTeamHappyPath:
    def test_exploit_event_drives_pipeline_to_successful_patch(self, blue_graph, exploit_event):
        with mocked_blue_agents([HIGH_CONFIDENCE_PATCH], [VALIDATION_SUCCESS]) as mocks:
            final = blue_graph.invoke(_state_from_event(exploit_event))

        assert final["outcome"] == PatchOutcome.SUCCESS
        assert final["phase"] == DefensePhase.COMPLETE
        assert final["failure_reason"] is None
        assert mocks.call_order == [
            "log_analysis",
            "root_cause",
            "patch_generation",
            "patch_validation",
        ]

    def test_every_agent_output_lands_in_state(self, blue_graph, exploit_event):
        with mocked_blue_agents([HIGH_CONFIDENCE_PATCH], [VALIDATION_SUCCESS]):
            final = blue_graph.invoke(_state_from_event(exploit_event))

        assert final["attack_summary"] == ATTACK_SUMMARY
        assert final["vulnerability_analysis"] == VULNERABILITY_ANALYSIS
        assert final["patch_diff"] == IN_SCOPE_DIFF
        assert final["patch_confidence"] == 0.9
        assert final["patch_strategy"] == HIGH_CONFIDENCE_PATCH["strategy_used"]
        assert final["patch_applies_cleanly"] is True
        assert final["functional_tests_passed"] is True
        assert final["exploit_blocked"] is True
        assert final["regression_introduced"] is False
        assert final["trace_id"]
        assert final["step_count"] == 4  # one per agent node

    def test_trigger_fields_are_forwarded_to_the_agents(self, blue_graph, exploit_event):
        with mocked_blue_agents([HIGH_CONFIDENCE_PATCH], [VALIDATION_SUCCESS]) as mocks:
            blue_graph.invoke(_state_from_event(exploit_event))

        assert mocks.log_analysis.call_args.kwargs == {
            "container_id": CONTAINER_ID,
            "exploit_timestamp": exploit_event.timestamp,
        }
        assert mocks.root_cause.call_args.kwargs["attack_summary"] == ATTACK_SUMMARY
        assert mocks.patch_gen.call_args.kwargs["attempt_number"] == 1
        validate_kwargs = mocks.patch_validation.call_args.kwargs
        assert validate_kwargs["allowed_patch_paths"] == [VULNERABLE_FILE]
        assert validate_kwargs["functional_health_url"] == HEALTH_URL
        assert validate_kwargs["exploit_replay_trace"] == REPLAY_TRACE

    def test_successful_attempt_is_written_to_episodic_memory(self, blue_graph, exploit_event):
        with mocked_blue_agents([HIGH_CONFIDENCE_PATCH], [VALIDATION_SUCCESS]) as mocks:
            blue_graph.invoke(_state_from_event(exploit_event))

        mocks.episode_log.assert_called_once()
        assert mocks.episode_log.call_args.kwargs["outcome"] == PatchOutcome.SUCCESS.value
        assert mocks.episode_log.call_args.kwargs["target_cve"] == exploit_event.cve_id


# ---------------------------------------------------------------------------
# Gate 1: patch confidence < 0.6 is never deployed
# ---------------------------------------------------------------------------


class TestLowConfidenceGate:
    def test_low_confidence_patch_is_regenerated_not_validated(self, blue_graph, exploit_event):
        assert LOW_CONFIDENCE_PATCH["confidence"] < MIN_CONFIDENCE_DEPLOY

        with mocked_blue_agents(
            [LOW_CONFIDENCE_PATCH, HIGH_CONFIDENCE_PATCH], [VALIDATION_SUCCESS]
        ) as mocks:
            final = blue_graph.invoke(_state_from_event(exploit_event))

        # The low-confidence patch went straight back to generation — the
        # validator only ever saw the regenerated, high-confidence one.
        assert mocks.call_order == [
            "log_analysis",
            "root_cause",
            "patch_generation",
            "patch_generation",
            "patch_validation",
        ]
        assert mocks.patch_validation.call_count == 1
        assert final["patch_confidence"] == HIGH_CONFIDENCE_PATCH["confidence"]
        assert final["outcome"] == PatchOutcome.SUCCESS

    def test_rejection_reason_is_recorded_in_supervisor_notes(self, blue_graph, exploit_event):
        with mocked_blue_agents(
            [LOW_CONFIDENCE_PATCH, HIGH_CONFIDENCE_PATCH], [VALIDATION_SUCCESS]
        ):
            final = blue_graph.invoke(_state_from_event(exploit_event))

        rejections = [n for n in final["supervisor_notes"] if n.startswith("Patch rejected:")]
        assert rejections == [
            f"Patch rejected: confidence 0.4 below {MIN_CONFIDENCE_DEPLOY}",
        ]

    @pytest.mark.parametrize("confidence", [None, 0.0, 0.59])
    def test_route_regenerates_for_any_sub_threshold_confidence(self, exploit_event, confidence):
        state = _state_from_event(exploit_event)
        state.update(
            phase=DefensePhase.PATCH_GENERATION,
            vulnerability_analysis=VULNERABILITY_ANALYSIS,
            patch_diff=IN_SCOPE_DIFF,
            patch_confidence=confidence,
        )
        assert supervisor_route(state) == "patch_generation_node"

    def test_route_deploys_at_the_threshold(self, exploit_event):
        state = _state_from_event(exploit_event)
        state.update(
            phase=DefensePhase.PATCH_GENERATION,
            vulnerability_analysis=VULNERABILITY_ANALYSIS,
            patch_diff=IN_SCOPE_DIFF,
            patch_confidence=MIN_CONFIDENCE_DEPLOY,
        )
        assert supervisor_route(state) == "patch_validation_node"


# ---------------------------------------------------------------------------
# Gate 2: patches outside allowed_patch_paths are rejected
# ---------------------------------------------------------------------------


class TestAllowedPatchPathsGate:
    def test_out_of_scope_patch_is_rejected_then_in_scope_patch_succeeds(
        self, blue_graph, exploit_event
    ):
        """Full pipeline with the REAL allowed_patch_paths whitelist in the loop."""
        with mocked_blue_agents(
            [OUT_OF_SCOPE_PATCH, HIGH_CONFIDENCE_PATCH], _scope_checked_validation
        ) as mocks:
            final = blue_graph.invoke(_state_from_event(exploit_event))

        assert mocks.call_order == [
            "log_analysis",
            "root_cause",
            "patch_generation",
            "patch_validation",  # wp-config.php — rejected on scope
            "patch_generation",
            "patch_validation",  # class-wpdb.php — accepted
        ]
        assert final["outcome"] == PatchOutcome.SUCCESS
        assert final["patch_diff"] == IN_SCOPE_DIFF
        assert any(
            n.startswith("Patch rejected: validation failed") for n in final["supervisor_notes"]
        )

    @pytest.mark.parametrize(
        "bad_diff",
        [
            pytest.param(OUT_OF_SCOPE_DIFF, id="unrelated-file"),
            pytest.param(TRAVERSAL_DIFF, id="path-traversal"),
        ],
    )
    def test_validation_node_rejects_out_of_scope_patch(self, exploit_event, bad_diff):
        """
        Drives the real PatchValidationAgent + real BlueTeamTransport scope
        check through patch_validation_node. deploy_patch short-circuits on the
        violation, so nothing is executed against a container.
        """
        state = _state_from_event(exploit_event)
        state.update(
            phase=DefensePhase.PATCH_GENERATION,
            vulnerability_analysis=VULNERABILITY_ANALYSIS,
            patch_diff=bad_diff,
            patch_confidence=0.88,
            patch_strategy="out of scope edit",
        )

        with (
            patch("agents.blue_team.supervisor.TraceLogger"),
            patch("agents.blue_team.supervisor.PatchGenerationAgent"),
            patch("agents.blue_team.patch_validation_agent.get_client"),
            patch("agents.shared.mcp_transport.subprocess") as no_subprocess,
        ):
            result = patch_validation_node(state)

        no_subprocess.run.assert_not_called()
        assert result["patch_applies_cleanly"] is False
        assert result["functional_tests_passed"] is False
        assert result["exploit_blocked"] is False
        assert result["regression_introduced"] is False

        finalized = finalize_node(result)
        assert finalized["outcome"] == PatchOutcome.FAILURE
        assert finalized["phase"] == DefensePhase.FAILED

    def test_route_refuses_to_generate_without_allowed_patch_paths(self, exploit_event):
        state = _state_from_event(exploit_event)
        state.update(
            phase=DefensePhase.ROOT_CAUSE,
            vulnerability_analysis={**VULNERABILITY_ANALYSIS, "allowed_patch_paths": []},
        )
        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.FAILURE
        assert "allowed_patch_paths" in state["failure_reason"]


# ---------------------------------------------------------------------------
# Gate 3: at most 3 patch attempts per vulnerability
# ---------------------------------------------------------------------------


class TestPatchAttemptCap:
    def test_route_terminates_once_the_cap_is_reached(self, exploit_event):
        state = _state_from_event(exploit_event)
        state.update(
            phase=DefensePhase.PATCH_VALIDATION,
            vulnerability_analysis=VULNERABILITY_ANALYSIS,
            patch_attempt_count=MAX_PATCH_ATTEMPTS,
            exploit_blocked=False,
            functional_tests_passed=True,
        )

        assert supervisor_route(state) == END
        assert state["outcome"] == PatchOutcome.FAILURE
        assert state["phase"] == DefensePhase.FAILED
        assert f"Max patch attempts ({MAX_PATCH_ATTEMPTS})" in state["failure_reason"]

    def test_route_still_retries_on_the_last_allowed_attempt(self, exploit_event):
        state = _state_from_event(exploit_event)
        state.update(
            phase=DefensePhase.PATCH_VALIDATION,
            vulnerability_analysis=VULNERABILITY_ANALYSIS,
            patch_attempt_count=MAX_PATCH_ATTEMPTS - 1,
            exploit_blocked=False,
            functional_tests_passed=True,
        )

        assert supervisor_route(state) == "patch_generation_node"
        assert state["patch_attempt_count"] == MAX_PATCH_ATTEMPTS

    def test_repeated_validation_failure_terminates_without_claiming_success(
        self, blue_graph, exploit_event
    ):
        with mocked_blue_agents([HIGH_CONFIDENCE_PATCH], [VALIDATION_EXPLOIT_STILL_WORKS]) as mocks:
            final = blue_graph.invoke(
                _state_from_event(exploit_event), config={"recursion_limit": 100}
            )

        assert final["outcome"] != PatchOutcome.SUCCESS
        assert final["phase"] != DefensePhase.COMPLETE
        assert final["step_count"] <= MAX_STEPS
        assert mocks.patch_gen.call_count == mocks.patch_validation.call_count
        assert any("TERMINATED" in note for note in final["supervisor_notes"])

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Known supervisor defect: patch_attempt_count is incremented inside "
            "supervisor_route(), a LangGraph conditional edge. Conditional edges "
            "get a read-only copy of the channel values, so the increment (and the "
            "_terminate() outcome write) is discarded. The retry loop is therefore "
            "only stopped by MAX_STEPS, not by MAX_PATCH_ATTEMPTS. Un-xfail this "
            "once the counter is incremented inside patch_generation_node."
        ),
    )
    def test_graph_stops_after_three_patch_attempts(self, blue_graph, exploit_event):
        with mocked_blue_agents([HIGH_CONFIDENCE_PATCH], [VALIDATION_EXPLOIT_STILL_WORKS]) as mocks:
            final = blue_graph.invoke(
                _state_from_event(exploit_event), config={"recursion_limit": 100}
            )

        assert mocks.patch_gen.call_count == MAX_PATCH_ATTEMPTS
        assert final["patch_attempt_count"] == MAX_PATCH_ATTEMPTS
        assert final["outcome"] == PatchOutcome.FAILURE
        assert final["phase"] == DefensePhase.FAILED
