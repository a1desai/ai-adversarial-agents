# =============================================================================
# tests/unit/test_benchmark_runner.py
# OWNER: Eval Hire
# MARKERS: unit (injected pipeline runners — no LangGraph/Ollama/Docker)
# PURPOSE: Tests for evaluation/benchmark_runner.py — end-to-end orchestration,
#          trace-ID keying, conditional Blue Team, and resumability (#16).
# =============================================================================

import json
import uuid

import pytest

from evaluation.benchmark_runner import (
    SCHEMA_VERSION,
    SUITES,
    BenchmarkRunner,
    BlueEngagement,
    RedEngagement,
    _zero_blue_metrics,
    _zero_red_metrics,
)
from evaluation.reward_red import RedTeamRunMetrics

pytestmark = pytest.mark.unit

SUITE = "cvebench"
SUITE_SIZE = len(SUITES[SUITE])


def _red(outcome: str) -> RedEngagement:
    """A Red engagement with realistic metrics for the given outcome."""
    succeeded = outcome == "success"
    metrics = RedTeamRunMetrics(
        successful_exploits=1 if succeeded else 0,
        total_targets_attempted=1,
        total_time_seconds=120.0,
        max_time_seconds=900,
        unique_attack_types_achieved=1 if succeeded else 0,
        total_tokens_used=30_000,
        success_after_retry=0,
        total_retries=0,
        ungrounded_actions=0,
        total_actions=12,
    )
    return RedEngagement(
        str(uuid.uuid4()), outcome, metrics, ["rce"] if succeeded else [], succeeded
    )


def make_red_runner(succeed_on=(), counter=None, raise_on_call=None):
    """Fake red runner. Optionally counts calls or raises mid-suite (crash sim)."""

    def runner(target, max_seconds):
        if counter is not None:
            counter.append(target.cve_id)
        if raise_on_call is not None and len(counter or []) == raise_on_call:
            raise RuntimeError("simulated crash")
        return _red("success" if target.cve_id in succeed_on else "failure")

    return runner


def make_blue_runner(counter=None):
    def runner(target, max_seconds):
        if counter is not None:
            counter.append(target.cve_id)
        return BlueEngagement(
            str(uuid.uuid4()), "success", _zero_blue_metrics(), exploit_blocked=True
        )

    return runner


def test_runs_all_targets_end_to_end(tmp_path):
    out = tmp_path / "run.json"
    runner = BenchmarkRunner(
        SUITE, out, red_runner=make_red_runner(), blue_runner=make_blue_runner()
    )
    results = runner.run()

    assert len(results) == SUITE_SIZE
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["suite"] == SUITE
    assert data["total_targets"] == SUITE_SIZE
    for record in data["results"].values():
        assert record["red"]["reward"]["composite"] is not None
        assert 0.0 <= record["red"]["reward"]["efficiency"] <= 1.0
        assert record["outcome"] in ("success", "failure", "timeout", "error")


def test_results_keyed_by_trace_id(tmp_path):
    out = tmp_path / "run.json"
    runner = BenchmarkRunner(SUITE, out, red_runner=make_red_runner())
    results = runner.run()
    for key, record in results.items():
        assert key == record["red"]["trace_id"]


def test_blue_runs_only_on_red_success(tmp_path):
    out = tmp_path / "run.json"
    target0 = SUITES[SUITE][0].cve_id
    blue_calls: list[str] = []
    runner = BenchmarkRunner(
        SUITE,
        out,
        red_runner=make_red_runner(succeed_on={target0}),
        blue_runner=make_blue_runner(counter=blue_calls),
    )
    results = runner.run()

    assert blue_calls == [target0]  # blue ran exactly once, for the one success
    for record in results.values():
        if record["cve_id"] == target0:
            assert record["blue"] is not None and record["blue"]["exploit_blocked"]
        else:
            assert record["blue"] is None


def test_resume_skips_already_recorded_targets(tmp_path):
    out = tmp_path / "run.json"
    # First pass records the whole suite.
    BenchmarkRunner(SUITE, out, red_runner=make_red_runner()).run()

    # Second pass over the same file should run zero targets.
    calls: list[str] = []
    BenchmarkRunner(SUITE, out, red_runner=make_red_runner(counter=calls)).run()
    assert calls == []


def test_unknown_suite_raises(tmp_path):
    with pytest.raises(ValueError):
        BenchmarkRunner("does-not-exist", tmp_path / "x.json")


def test_interrupted_run_matches_uninterrupted(tmp_path):
    succeed = {SUITES[SUITE][1].cve_id}

    # Reference: one clean uninterrupted run.
    ref_out = tmp_path / "ref.json"
    ref = BenchmarkRunner(SUITE, ref_out, red_runner=make_red_runner(succeed_on=succeed)).run()
    ref_by_cve = {r["cve_id"]: r["outcome"] for r in ref.values()}

    # Interrupted run: crash on the 3rd target.
    out = tmp_path / "run.json"
    calls: list[str] = []
    crashing = make_red_runner(succeed_on=succeed, counter=calls, raise_on_call=3)
    with pytest.raises(RuntimeError):
        BenchmarkRunner(SUITE, out, red_runner=crashing).run()

    # The two targets completed before the crash are durably persisted.
    partial = json.loads(out.read_text())["results"]
    assert len(partial) == 2

    # Resume with a healthy runner.
    resumed = BenchmarkRunner(SUITE, out, red_runner=make_red_runner(succeed_on=succeed)).run()
    resumed_by_cve = {r["cve_id"]: r["outcome"] for r in resumed.values()}

    assert resumed_by_cve == ref_by_cve
    assert len(resumed) == SUITE_SIZE


def test_zero_metrics_helpers_are_reward_safe():
    # Sanity: the zero-metric fallbacks never divide by zero.
    from evaluation.benchmark_runner import compute_blue_reward, compute_red_reward

    assert compute_red_reward(_zero_red_metrics()) is not None
    assert compute_blue_reward(_zero_blue_metrics()) is not None
