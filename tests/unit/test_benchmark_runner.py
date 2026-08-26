# =============================================================================
# tests/unit/test_benchmark_runner.py
# OWNER: Red Team Hire
# MARKERS: unit (no Ollama, Docker, or ChromaDB required — all pipelines mocked)
# PURPOSE: Tests for BenchmarkRunner and helpers.
# RUN: pytest tests/unit/test_benchmark_runner.py -v
# =============================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from evaluation.benchmark_runner import (
    BenchmarkRunner,
    BenchmarkTarget,
    EngagementResult,
    _build_blue_metrics,
    _build_red_metrics,
    _count_diff_lines,
    _load_checkpoint,
    _save_checkpoint,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TARGET = BenchmarkTarget(
    cve="CVE-2019-9053",
    container_id="target_dvwa",
    url="http://localhost:8080",
    health_url="http://localhost:8080/index.php",
)

_RED_SUCCESS_STATE = {
    "trace_id": "trace-abc-123",
    "outcome": "success",
    "step_count": 5,
    "token_count": 1200,
    "elapsed_seconds": 45.0,
    "attack_goals_achieved": ["database_access"],
    "retry_count": 0,
    "payload_used": "curl -s http://localhost:8080",
    "failure_reason": None,
    "supervisor_notes": [],
}

_RED_FAILURE_STATE = {
    **_RED_SUCCESS_STATE,
    "trace_id": "trace-fail-456",
    "outcome": "failure",
    "attack_goals_achieved": [],
}

_BLUE_SUCCESS_STATE = {
    "trace_id": "trace-blue-789",
    "outcome": "success",
    "step_count": 8,
    "token_count": 2000,
    "elapsed_seconds": 90.0,
    "exploit_blocked": True,
    "functional_tests_passed": True,
    "patch_diff": "--- a/file.php\n+++ b/file.php\n@@ -1,3 +1,3 @@\n-$q = $id;\n+$q = intval($id);\n",
    "failure_reason": None,
    "supervisor_notes": [],
}

_BLUE_FAILURE_STATE = {
    **_BLUE_SUCCESS_STATE,
    "outcome": "failure",
    "exploit_blocked": False,
}


def _make_result(red_outcome="success", blue_outcome="success") -> EngagementResult:
    return EngagementResult(
        trace_id="trace-abc-123",
        target_cve="CVE-2019-9053",
        container_id="target_dvwa",
        red_outcome=red_outcome,
        red_steps=5,
        red_tokens=1200,
        red_elapsed_seconds=45.0,
        red_attack_goals=["database_access"],
        red_retry_count=0,
        red_payload_used="curl -s ...",
        blue_outcome=blue_outcome,
        blue_steps=8,
        blue_tokens=2000,
        blue_elapsed_seconds=90.0,
        blue_exploit_blocked=(blue_outcome == "success"),
        blue_functional_ok=True,
        blue_patch_lines_changed=2,
    )


# ---------------------------------------------------------------------------
# _count_diff_lines
# ---------------------------------------------------------------------------


class TestCountDiffLines:
    def test_counts_added_and_removed_lines(self):
        diff = "--- a/f.php\n+++ b/f.php\n@@ -1 +1 @@\n-old\n+new\n"
        assert _count_diff_lines(diff) == 2

    def test_ignores_file_headers(self):
        diff = "--- a/f.php\n+++ b/f.php\n@@ -1 +1 @@\n+added\n"
        assert _count_diff_lines(diff) == 1

    def test_empty_diff_returns_zero(self):
        assert _count_diff_lines("") == 0

    def test_none_returns_zero(self):
        assert _count_diff_lines(None) == 0


# ---------------------------------------------------------------------------
# _build_red_metrics
# ---------------------------------------------------------------------------


class TestBuildRedMetrics:
    def test_success_sets_successful_exploits_to_1(self):
        result = _make_result(red_outcome="success", blue_outcome=None)
        metrics = _build_red_metrics(result)
        assert metrics.successful_exploits == 1
        assert metrics.total_targets_attempted == 1

    def test_failure_sets_successful_exploits_to_0(self):
        result = _make_result(red_outcome="failure", blue_outcome=None)
        metrics = _build_red_metrics(result)
        assert metrics.successful_exploits == 0

    def test_retry_fields_populated(self):
        result = _make_result()
        result.red_retry_count = 2
        result.red_outcome = "success"
        metrics = _build_red_metrics(result)
        assert metrics.total_retries == 2
        assert metrics.success_after_retry == 1

    def test_no_retry_on_first_attempt(self):
        result = _make_result()
        result.red_retry_count = 0
        metrics = _build_red_metrics(result)
        assert metrics.success_after_retry == 0


# ---------------------------------------------------------------------------
# _build_blue_metrics
# ---------------------------------------------------------------------------


class TestBuildBlueMetrics:
    def test_returns_none_when_blue_not_run(self):
        result = _make_result(red_outcome="failure", blue_outcome=None)
        result.blue_outcome = None
        assert _build_blue_metrics(result) is None

    def test_success_sets_successful_patches_to_1(self):
        result = _make_result(blue_outcome="success")
        metrics = _build_blue_metrics(result)
        assert metrics.successful_patches == 1

    def test_failure_sets_successful_patches_to_0(self):
        result = _make_result(blue_outcome="failure")
        metrics = _build_blue_metrics(result)
        assert metrics.successful_patches == 0


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------


class TestCheckpoint:
    def test_save_and_load_roundtrip(self, tmp_path):
        with patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "ckpt.json"):
            _save_checkpoint({"CVE-2019-9053", "CVE-2024-22120"})
            loaded = _load_checkpoint()
        assert "CVE-2019-9053" in loaded
        assert "CVE-2024-22120" in loaded

    def test_load_missing_file_returns_empty_set(self, tmp_path):
        with patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "nonexistent.json"):
            assert _load_checkpoint() == set()


# ---------------------------------------------------------------------------
# BenchmarkRunner.run
# ---------------------------------------------------------------------------


class TestBenchmarkRunner:
    def _patched_runner(self, red_state, blue_state=None):
        runner = BenchmarkRunner(red_only=(blue_state is None))
        runner._run_engagement = MagicMock(
            return_value=EngagementResult(
                trace_id=red_state["trace_id"],
                target_cve=_TARGET.cve,
                container_id=_TARGET.container_id,
                red_outcome=red_state["outcome"],
                red_steps=red_state["step_count"],
                red_tokens=red_state["token_count"],
                red_elapsed_seconds=red_state["elapsed_seconds"],
                red_attack_goals=red_state["attack_goals_achieved"],
                red_retry_count=red_state["retry_count"],
                red_payload_used=red_state["payload_used"],
                blue_outcome=blue_state["outcome"] if blue_state else None,
                blue_exploit_blocked=blue_state.get("exploit_blocked") if blue_state else None,
                blue_functional_ok=blue_state.get("functional_tests_passed")
                if blue_state
                else None,
                blue_steps=blue_state.get("step_count") if blue_state else None,
                blue_tokens=blue_state.get("token_count") if blue_state else None,
                blue_elapsed_seconds=blue_state.get("elapsed_seconds") if blue_state else None,
                blue_patch_lines_changed=2 if blue_state else None,
            )
        )
        return runner

    def test_esr_one_of_one(self, tmp_path):
        runner = self._patched_runner(_RED_SUCCESS_STATE, _BLUE_SUCCESS_STATE)
        with (
            patch("evaluation.benchmark_runner.RESULTS_FILE", tmp_path / "r.json"),
            patch("evaluation.benchmark_runner.SUMMARY_FILE", tmp_path / "s.json"),
            patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "c.json"),
        ):
            summary = runner.run([_TARGET])
        assert summary["esr"] == 1.0
        assert summary["red_successes"] == 1

    def test_esr_zero_on_failure(self, tmp_path):
        runner = self._patched_runner(_RED_FAILURE_STATE)
        with (
            patch("evaluation.benchmark_runner.RESULTS_FILE", tmp_path / "r.json"),
            patch("evaluation.benchmark_runner.SUMMARY_FILE", tmp_path / "s.json"),
            patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "c.json"),
        ):
            summary = runner.run([_TARGET])
        assert summary["esr"] == 0.0

    def test_psr_one_on_success(self, tmp_path):
        runner = self._patched_runner(_RED_SUCCESS_STATE, _BLUE_SUCCESS_STATE)
        with (
            patch("evaluation.benchmark_runner.RESULTS_FILE", tmp_path / "r.json"),
            patch("evaluation.benchmark_runner.SUMMARY_FILE", tmp_path / "s.json"),
            patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "c.json"),
        ):
            summary = runner.run([_TARGET])
        assert summary["psr"] == 1.0

    def test_results_keyed_by_trace_id(self, tmp_path):
        results_file = tmp_path / "r.json"
        runner = self._patched_runner(_RED_SUCCESS_STATE, _BLUE_SUCCESS_STATE)
        with (
            patch("evaluation.benchmark_runner.RESULTS_FILE", results_file),
            patch("evaluation.benchmark_runner.SUMMARY_FILE", tmp_path / "s.json"),
            patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "c.json"),
        ):
            runner.run([_TARGET])
        saved = json.loads(results_file.read_text())
        assert "trace-abc-123" in saved

    def test_resume_skips_completed_cve(self, tmp_path):
        runner = self._patched_runner(_RED_SUCCESS_STATE, _BLUE_SUCCESS_STATE)
        runner.resume = True
        ckpt = tmp_path / "c.json"
        ckpt.write_text(json.dumps({"completed": [_TARGET.cve]}))
        with (
            patch("evaluation.benchmark_runner.RESULTS_FILE", tmp_path / "r.json"),
            patch("evaluation.benchmark_runner.SUMMARY_FILE", tmp_path / "s.json"),
            patch("evaluation.benchmark_runner.CHECKPOINT_FILE", ckpt),
        ):
            runner.run([_TARGET])
        runner._run_engagement.assert_not_called()

    def test_blue_skipped_when_red_fails(self, tmp_path):
        runner = self._patched_runner(_RED_FAILURE_STATE)
        with (
            patch("evaluation.benchmark_runner.RESULTS_FILE", tmp_path / "r.json"),
            patch("evaluation.benchmark_runner.SUMMARY_FILE", tmp_path / "s.json"),
            patch("evaluation.benchmark_runner.CHECKPOINT_FILE", tmp_path / "c.json"),
        ):
            summary = runner.run([_TARGET])
        assert summary["blue_successes"] == 0
        assert summary["psr"] == 0.0
