# =============================================================================
# evaluation/report_generator.py
# OWNER: Eval Hire
# PURPOSE: Turn benchmark_results.json + summary.json into the final Markdown
#          benchmark report (aggregate table, per-engagement table, failure
#          categories), with optional baseline-vs-final deltas.
# REFERENCE: issues.md #56
# =============================================================================
#
# NOTE: AI-assisted (drafted with Claude), human-reviewed.
#
# HARD RULE: this module NEVER invents a number. Every figure printed is read
#            straight out of the input dicts. A field that is absent renders as
#            "n/a" — it is never defaulted to 0, and it is never recomputed.
#
# INPUTS (produced by evaluation/benchmark_runner.py):
#   <results-dir>/benchmark_results.json  → {trace_id: engagement_record}
#   <results-dir>/summary.json            → aggregate metrics (ESR, PSR, ...)
#   <baseline>.json                       → optional earlier summary, for deltas
#
# CLI:
#   python evaluation/report_generator.py \
#       --results-dir evaluation/results \
#       --out docs/final_benchmark_report.md
# =============================================================================

import argparse
import json
import sys
from pathlib import Path
from typing import Any

RESULTS_FILENAME = "benchmark_results.json"
SUMMARY_FILENAME = "summary.json"

DEFAULT_RESULTS_DIR = Path(__file__).parent / "results"
DEFAULT_OUT = Path(__file__).parent.parent / "docs" / "final_benchmark_report.md"

# Rendered whenever a field is missing from the input data.
NA = "n/a"

# Outcome value that means "this engagement did what it set out to do".
SUCCESS_OUTCOME = "success"


# ---------------------------------------------------------------------------
# Formatting helpers — all of them return NA rather than guessing a value
# ---------------------------------------------------------------------------


def _as_float(value: Any) -> float | None:
    """Coerce to float, or None if the value is missing / not numeric."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _fmt_ratio(value: Any) -> str:
    """Format a reward-style number to 3 decimal places."""
    number = _as_float(value)
    return NA if number is None else f"{number:.3f}"


def _fmt_pct(value: Any) -> str:
    """Format a 0..1 rate as a percentage (ESR / PSR)."""
    number = _as_float(value)
    return NA if number is None else f"{number * 100:.1f}%"


def _fmt_count(value: Any) -> str:
    """Format an integer count."""
    number = _as_float(value)
    return NA if number is None else f"{number:g}"


def _delta_ratio(final: Any, baseline: Any) -> str:
    final_n, base_n = _as_float(final), _as_float(baseline)
    if final_n is None or base_n is None:
        return NA
    return f"{final_n - base_n:+.3f}"


def _delta_pct(final: Any, baseline: Any) -> str:
    """Percentage-point delta between two 0..1 rates."""
    final_n, base_n = _as_float(final), _as_float(baseline)
    if final_n is None or base_n is None:
        return NA
    return f"{(final_n - base_n) * 100:+.1f} pp"


def _delta_count(final: Any, baseline: Any) -> str:
    final_n, base_n = _as_float(final), _as_float(baseline)
    if final_n is None or base_n is None:
        return NA
    return f"{final_n - base_n:+g}"


def _cell(value: Any) -> str:
    """Render an arbitrary value as a Markdown table cell."""
    if value is None or value == "":
        return NA
    return str(value).replace("|", "\\|")


def _dig(data: Any, path: tuple[str, ...]) -> Any:
    """Walk a nested dict by key path. Returns None if any hop is missing."""
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Build a Markdown table as a list of lines."""
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


# ---------------------------------------------------------------------------
# Aggregate metric spec — (label, key path in summary, value fmt, delta fmt)
# ---------------------------------------------------------------------------

_AGGREGATE_METRICS: list[tuple[str, tuple[str, ...], Any, Any]] = [
    ("Total targets", ("total_targets",), _fmt_count, _delta_count),
    ("Red ESR", ("red", "esr"), _fmt_pct, _delta_pct),
    ("Blue PSR", ("blue", "psr"), _fmt_pct, _delta_pct),
    ("Mean red reward", ("red", "mean_reward"), _fmt_ratio, _delta_ratio),
    ("Mean blue reward", ("blue", "mean_reward"), _fmt_ratio, _delta_ratio),
    ("Successful exploits", ("red", "successful_exploits"), _fmt_count, _delta_count),
    ("Successful patches", ("blue", "successful_patches"), _fmt_count, _delta_count),
]


def _normalise_summary(raw: dict | None) -> dict:
    """
    Accept either a bare summary dict or a wrapper of the form
    {"summary": {...}} (baseline files are sometimes stored wrapped).
    """
    if not isinstance(raw, dict):
        return {}
    inner = raw.get("summary")
    return inner if isinstance(inner, dict) else raw


def _baseline_label(baseline: dict) -> str:
    for key in ("label", "name", "generated_at"):
        value = baseline.get(key)
        if value:
            return str(value)
    return "baseline"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------


def _metadata_section(results: dict, summary: dict, baseline: dict | None) -> list[str]:
    lines = ["## Run Metadata", ""]
    rows = [
        ["Generated at", _cell(summary.get("generated_at"))],
        ["Total targets", _fmt_count(summary.get("total_targets"))],
        ["Engagements recorded", _fmt_count(len(results))],
        ["Baseline", _cell(_baseline_label(baseline)) if baseline else NA],
    ]
    lines.extend(_md_table(["Field", "Value"], rows))
    lines.append("")
    return lines


def _aggregate_section(summary: dict, baseline: dict | None) -> list[str]:
    lines = ["## Aggregate Results", ""]

    if baseline:
        headers = ["Metric", "Baseline", "Final", "Delta"]
        rows = [
            [
                label,
                fmt(_dig(baseline, path)),
                fmt(_dig(summary, path)),
                delta_fmt(_dig(summary, path), _dig(baseline, path)),
            ]
            for label, path, fmt, delta_fmt in _AGGREGATE_METRICS
        ]
    else:
        headers = ["Metric", "Value"]
        rows = [[label, fmt(_dig(summary, path))] for label, path, fmt, _ in _AGGREGATE_METRICS]

    lines.extend(_md_table(headers, rows))
    lines.append("")
    return lines


def _engagement_section(results: dict) -> list[str]:
    lines = ["## Per-Engagement Results", ""]

    if not results:
        lines.append("_No engagements recorded._")
        lines.append("")
        return lines

    rows = []
    for trace_id in sorted(results):
        record = results[trace_id]
        record = record if isinstance(record, dict) else {}
        rows.append(
            [
                _cell(record.get("trace_id", trace_id)),
                _cell(record.get("target_cve")),
                _cell(_dig(record, ("red", "outcome"))),
                _cell(_dig(record, ("blue", "outcome"))),
                _fmt_ratio(record.get("red_reward")),
                _fmt_ratio(record.get("blue_reward")),
            ]
        )

    headers = [
        "Trace ID",
        "CVE",
        "Red Outcome",
        "Blue Outcome",
        "Red Reward",
        "Blue Reward",
    ]
    lines.extend(_md_table(headers, rows))
    lines.append("")
    return lines


def failure_categories(results: dict) -> list[tuple[str, int]]:
    """
    Count non-success outcomes across both teams.

    Categories are strictly derived from outcome values present in the data —
    nothing is inferred. A record with no outcome field is counted under
    "<team>: n/a" so the gap stays visible instead of silently vanishing.
    Sorted by count desc, then alphabetically for determinism.
    """
    counts: dict[str, int] = {}
    for record in results.values():
        if not isinstance(record, dict):
            continue
        for team in ("red", "blue"):
            outcome = _dig(record, (team, "outcome"))
            if isinstance(outcome, str) and outcome.lower() == SUCCESS_OUTCOME:
                continue
            label = f"{team}: {outcome}" if outcome else f"{team}: {NA}"
            counts[label] = counts.get(label, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _failure_section(results: dict) -> list[str]:
    lines = ["## Top Failure Categories", ""]
    categories = failure_categories(results)

    if not categories:
        lines.append("_No non-success outcomes recorded._")
        lines.append("")
        return lines

    rows = [[_cell(label), str(count)] for label, count in categories]
    lines.extend(_md_table(["Category", "Count"], rows))
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_report(results: dict, summary: dict, baseline: dict | None = None) -> str:
    """
    Render the full Markdown benchmark report.

    Pure function — no file I/O — so it is unit-testable with synthetic dicts.

    Args:
        results:  benchmark_results.json contents, keyed by trace_id.
        summary:  summary.json contents (aggregate metrics).
        baseline: optional earlier summary dict; when supplied the aggregate
                  table gains Baseline / Final / Delta columns.

    Returns:
        The report as a Markdown string.
    """
    results = results if isinstance(results, dict) else {}
    summary = _normalise_summary(summary)
    baseline = _normalise_summary(baseline) if baseline else None

    lines = ["# Adversarial Benchmark Report", ""]
    lines.extend(_metadata_section(results, summary, baseline))
    lines.extend(_aggregate_section(summary, baseline))
    lines.extend(_engagement_section(results))
    lines.extend(_failure_section(results))

    return "\n".join(lines).rstrip() + "\n"


def load_json(path: Path) -> dict:
    """Load a JSON object from disk. Raises FileNotFoundError if missing."""
    with open(path) as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}, got {type(data).__name__}")
    return data


def build_report_from_dir(results_dir: Path, baseline_path: Path | None = None) -> str:
    """Read the results directory (and optional baseline) and render the report."""
    results = load_json(Path(results_dir) / RESULTS_FILENAME)
    summary = load_json(Path(results_dir) / SUMMARY_FILENAME)
    baseline = load_json(Path(baseline_path)) if baseline_path else None
    return generate_report(results, summary, baseline)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="report_generator",
        description="Generate the final Markdown benchmark report from benchmark results.",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help=f"Directory holding {RESULTS_FILENAME} and {SUMMARY_FILENAME}.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Optional baseline summary JSON (e.g. evaluation/baselines/v0.json) for deltas.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"Write the report here (default: stdout). Suggested: {DEFAULT_OUT}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        report = build_report_from_dir(args.results_dir, args.baseline)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[report_generator] {exc}", file=sys.stderr)
        return 1

    if args.out is None:
        print(report, end="")
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report)
        print(f"[report_generator] Wrote report to {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
