# =============================================================================
# tests/unit/test_report_generator.py
# OWNER: Eval Hire
# MARKERS: unit
# PURPOSE: Tests for evaluation/report_generator.py
# RUN: pytest tests/unit/test_report_generator.py -v
# REFERENCE: issues.md #56
# =============================================================================
#
# NOTE: AI-assisted (drafted with Claude), human-reviewed.
# =============================================================================

import json

import pytest

from evaluation.report_generator import (
    build_report_from_dir,
    failure_categories,
    generate_report,
    main,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Synthetic fixtures — shaped exactly like benchmark_runner.py's output
# (benchmark_results.json: flat red_*/blue_* keys; summary.json: top-level
# esr/psr, {red,blue}_reward.composite, {red,blue}_successes, run_timestamp).
# ---------------------------------------------------------------------------


def _engagement(
    trace_id: str,
    cve: str,
    red_outcome: str,
    blue_outcome: str,
    red_steps: int = 4,
    blue_steps: int = 6,
) -> dict:
    return {
        "trace_id": trace_id,
        "target_cve": cve,
        "container_id": "target_dvwa",
        "red_outcome": red_outcome,
        "red_steps": red_steps,
        "red_tokens": 0,
        "red_elapsed_seconds": 0.0,
        "red_attack_goals": ["database_access"],
        "red_retry_count": 0,
        "blue_outcome": blue_outcome,
        "blue_steps": blue_steps,
        "blue_tokens": 0,
        "blue_elapsed_seconds": 0.0,
        "blue_exploit_blocked": blue_outcome == "success",
        "blue_functional_ok": blue_outcome == "success",
        "blue_patch_lines_changed": 2,
        "timestamp": "2026-08-25T12:00:00+00:00",
    }


@pytest.fixture
def results() -> dict:
    return {
        "trace-aaa": _engagement("trace-aaa", "CVE-2024-1001", "success", "success", 4, 6),
        "trace-bbb": _engagement("trace-bbb", "CVE-2024-1002", "failure", "success", 8, 5),
        "trace-ccc": _engagement("trace-ccc", "CVE-2024-1003", "timeout", "regression", 30, 30),
        "trace-ddd": _engagement("trace-ddd", "CVE-2024-1004", "failure", "failure", 12, 30),
    }


@pytest.fixture
def summary() -> dict:
    return {
        "run_timestamp": "2026-08-25T12:00:00+00:00",
        "total_targets": 4,
        "red_successes": 1,
        "blue_successes": 2,
        "esr": 0.25,
        "psr": 0.5,
        "red_reward": {"composite": 0.24075},
        "blue_reward": {"composite": 0.4460},
    }


@pytest.fixture
def baseline() -> dict:
    return {
        "run_timestamp": "2026-07-01T09:00:00+00:00",
        "total_targets": 4,
        "red_successes": 2,
        "blue_successes": 1,
        "esr": 0.50,
        "psr": 0.25,
        "red_reward": {"composite": 0.40000},
        "blue_reward": {"composite": 0.30000},
    }


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


class TestReportStructure:
    def test_emits_all_required_sections(self, results, summary):
        report = generate_report(results, summary)
        assert report.startswith("# Adversarial Benchmark Report")
        for heading in (
            "## Run Metadata",
            "## Aggregate Results",
            "## Per-Engagement Results",
            "## Top Failure Categories",
        ):
            assert heading in report

    def test_metadata_includes_run_timestamp_and_counts(self, results, summary):
        report = generate_report(results, summary)
        assert "2026-08-25T12:00:00+00:00" in report
        assert "| Engagements recorded | 4 |" in report

    def test_report_ends_with_single_newline(self, results, summary):
        report = generate_report(results, summary)
        assert report.endswith("\n")
        assert not report.endswith("\n\n")


# ---------------------------------------------------------------------------
# Aggregate table
# ---------------------------------------------------------------------------


class TestAggregateTable:
    def test_rates_render_as_percentages(self, results, summary):
        report = generate_report(results, summary)
        assert "| Red ESR | 25.0% |" in report
        assert "| Blue PSR | 50.0% |" in report

    def test_mean_rewards_render_to_three_decimals(self, results, summary):
        report = generate_report(results, summary)
        assert "| Mean red reward | 0.241 |" in report
        assert "| Mean blue reward | 0.446 |" in report

    def test_success_counts_render(self, results, summary):
        report = generate_report(results, summary)
        assert "| Successful exploits | 1 |" in report
        assert "| Successful patches | 2 |" in report
        assert "| Total targets | 4 |" in report

    def test_no_baseline_means_two_column_table(self, results, summary):
        report = generate_report(results, summary)
        assert "| Metric | Value |" in report
        assert "| Metric | Baseline | Final | Delta |" not in report


# ---------------------------------------------------------------------------
# Baseline deltas
# ---------------------------------------------------------------------------


class TestBaselineDeltas:
    def test_baseline_adds_delta_columns(self, results, summary, baseline):
        report = generate_report(results, summary, baseline)
        assert "| Metric | Baseline | Final | Delta |" in report

    def test_negative_rate_delta_in_percentage_points(self, results, summary, baseline):
        # ESR fell 0.50 -> 0.25
        report = generate_report(results, summary, baseline)
        assert "| Red ESR | 50.0% | 25.0% | -25.0 pp |" in report

    def test_positive_rate_delta_in_percentage_points(self, results, summary, baseline):
        # PSR rose 0.25 -> 0.50
        report = generate_report(results, summary, baseline)
        assert "| Blue PSR | 25.0% | 50.0% | +25.0 pp |" in report

    def test_reward_deltas_are_signed_three_decimals(self, results, summary, baseline):
        report = generate_report(results, summary, baseline)
        assert "| Mean red reward | 0.400 | 0.241 | -0.159 |" in report
        assert "| Mean blue reward | 0.300 | 0.446 | +0.146 |" in report

    def test_count_deltas_are_signed(self, results, summary, baseline):
        report = generate_report(results, summary, baseline)
        assert "| Successful exploits | 2 | 1 | -1 |" in report
        assert "| Successful patches | 1 | 2 | +1 |" in report

    def test_baseline_label_appears_in_metadata(self, results, summary, baseline):
        report = generate_report(results, summary, baseline)
        assert "| Baseline | 2026-07-01T09:00:00+00:00 |" in report

    def test_baseline_may_be_wrapped_under_summary_key(self, results, summary, baseline):
        report = generate_report(results, summary, {"summary": baseline})
        assert "| Red ESR | 50.0% | 25.0% | -25.0 pp |" in report

    def test_missing_baseline_metric_renders_na_delta(self, results, summary):
        partial_baseline = {"esr": 0.5}
        report = generate_report(results, summary, partial_baseline)
        assert "| Red ESR | 50.0% | 25.0% | -25.0 pp |" in report
        # composite reward is absent from the baseline → baseline cell and delta are n/a
        assert "| Mean red reward | n/a | 0.241 | n/a |" in report


# ---------------------------------------------------------------------------
# Per-engagement table
# ---------------------------------------------------------------------------


class TestEngagementTable:
    def test_one_row_per_engagement_sorted_by_trace_id(self, results, summary):
        report = generate_report(results, summary)
        positions = [report.index(tid) for tid in ("trace-aaa", "trace-bbb", "trace-ccc")]
        assert positions == sorted(positions)

    def test_row_contains_cve_outcomes_and_steps(self, results, summary):
        report = generate_report(results, summary)
        assert "| trace-aaa | CVE-2024-1001 | success | 4 | success | 6 |" in report
        assert "| trace-ccc | CVE-2024-1003 | timeout | 30 | regression | 30 |" in report

    def test_empty_results_renders_placeholder(self, summary):
        report = generate_report({}, summary)
        assert "_No engagements recorded._" in report
        assert "| Engagements recorded | 0 |" in report


# ---------------------------------------------------------------------------
# Missing data → "n/a", never a fabricated number
# ---------------------------------------------------------------------------


class TestMissingFields:
    def test_empty_summary_renders_all_metrics_as_na(self, results):
        report = generate_report(results, {})
        assert "| Red ESR | n/a |" in report
        assert "| Blue PSR | n/a |" in report
        assert "| Mean red reward | n/a |" in report
        assert "| Mean blue reward | n/a |" in report
        assert "| Generated at | n/a |" in report

    def test_engagement_missing_fields_renders_na(self, summary):
        results = {"trace-zzz": {"trace_id": "trace-zzz"}}
        report = generate_report(results, summary)
        assert "| trace-zzz | n/a | n/a | n/a | n/a | n/a |" in report

    def test_zero_is_not_treated_as_missing(self, summary):
        results = {"trace-zero": _engagement("trace-zero", "CVE-0", "failure", "failure", 0, 0)}
        report = generate_report(results, summary)
        assert "| trace-zero | CVE-0 | failure | 0 | failure | 0 |" in report

    def test_no_baseline_renders_baseline_metadata_as_na(self, results, summary):
        report = generate_report(results, summary)
        assert "| Baseline | n/a |" in report

    def test_non_numeric_step_renders_na(self, summary):
        results = {"trace-bad": {"trace_id": "trace-bad", "red_steps": "oops"}}
        report = generate_report(results, summary)
        assert "| trace-bad | n/a | n/a | n/a | n/a | n/a |" in report


# ---------------------------------------------------------------------------
# Failure categories
# ---------------------------------------------------------------------------


class TestFailureCategories:
    def test_counts_non_success_outcomes_per_team(self, results):
        assert failure_categories(results) == [
            ("red: failure", 2),
            ("blue: failure", 1),
            ("blue: regression", 1),
            ("red: timeout", 1),
        ]

    def test_successes_are_excluded(self, results):
        labels = [label for label, _ in failure_categories(results)]
        assert "red: success" not in labels
        assert "blue: success" not in labels

    def test_missing_outcome_is_surfaced_as_na(self):
        categories = failure_categories({"t1": {"trace_id": "t1"}})
        assert categories == [("blue: n/a", 1), ("red: n/a", 1)]

    def test_section_renders_counts_sorted_desc(self, results, summary):
        report = generate_report(results, summary)
        section = report.split("## Top Failure Categories")[1]
        assert "| red: failure | 2 |" in section
        assert "| red: timeout | 1 |" in section
        assert section.index("red: failure") < section.index("red: timeout")

    def test_all_success_renders_placeholder(self, summary):
        clean = {"t1": _engagement("t1", "CVE-1", "success", "success")}
        report = generate_report(clean, summary)
        assert "_No non-success outcomes recorded._" in report


# ---------------------------------------------------------------------------
# File / CLI plumbing
# ---------------------------------------------------------------------------


class TestFileAndCli:
    @pytest.fixture
    def results_dir(self, tmp_path, results, summary):
        directory = tmp_path / "results"
        directory.mkdir()
        (directory / "benchmark_results.json").write_text(json.dumps(results))
        (directory / "summary.json").write_text(json.dumps(summary))
        return directory

    def test_build_report_from_dir_matches_pure_function(self, results_dir, results, summary):
        assert build_report_from_dir(results_dir) == generate_report(results, summary)

    def test_build_report_from_dir_with_baseline(self, results_dir, tmp_path, baseline):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(baseline))
        report = build_report_from_dir(results_dir, baseline_path)
        assert "| Metric | Baseline | Final | Delta |" in report

    def test_missing_results_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            build_report_from_dir(tmp_path)

    def test_cli_writes_out_file(self, results_dir, tmp_path):
        out = tmp_path / "nested" / "report.md"
        code = main(["--results-dir", str(results_dir), "--out", str(out)])
        assert code == 0
        assert out.exists()
        assert "# Adversarial Benchmark Report" in out.read_text()

    def test_cli_prints_to_stdout_without_out(self, results_dir, capsys):
        code = main(["--results-dir", str(results_dir)])
        assert code == 0
        assert "## Aggregate Results" in capsys.readouterr().out

    def test_cli_returns_nonzero_when_results_missing(self, tmp_path, capsys):
        code = main(["--results-dir", str(tmp_path)])
        assert code == 1
        assert "report_generator" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Real committed run — parses evaluation/results/ without error
# ---------------------------------------------------------------------------


class TestAgainstRealResults:
    def test_parses_the_committed_benchmark_run(self):
        from pathlib import Path

        import evaluation.report_generator as rg

        results_dir = Path(rg.__file__).parent / "results"
        if not (results_dir / "summary.json").exists():
            pytest.skip("no committed benchmark run present")
        report = build_report_from_dir(results_dir)
        # The committed smoke run is CVE-2019-9053 on DVWA: red success, blue failure.
        assert "# Adversarial Benchmark Report" in report
        assert "CVE-2019-9053" in report
        assert "| Red ESR | 100.0% |" in report
        assert "| Blue PSR | 0.0% |" in report
