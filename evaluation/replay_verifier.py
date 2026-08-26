# =============================================================================
# evaluation/replay_verifier.py
# OWNER: Eval Hire
# PURPOSE: Trace replay verification across every recorded engagement.
#          Enforces the trace_logger rule: a successful exploit or patch is
#          only valid if it can be reproduced by replaying the trace. Any
#          engagement whose replay diverges is marked INVALIDATED.
# REFERENCE: docs/issues.md #57 (trace replay verification) and the RULE banner
#            in evaluation/trace_logger.py.
# =============================================================================
#
# NOTE: AI-assisted (drafted with Claude), human-reviewed.
#
# WHY THIS IS OFFLINE
# -------------------
# Replaying against a live container needs Docker + the CVE-Bench targets, which
# is not available on every hire's machine (and never in CI). So "replay" here
# means: re-read the recorded events and prove the record is internally
# consistent and self-describing —
#   1. the trace file exists and has at least one event,
#   2. every event carries the trace_id it was filed under,
#   3. step_numbers are contiguous and monotonic starting at 1,
#   4. summary total_steps  == number of recorded events,
#   5. summary total_tokens == sum of per-event tokens_used,
#   6. summary outcome is consistent with the terminal event,
#   7. (optional) re-running the recorded inputs through an injected
#      `reexecute` callable reproduces the recorded outputs byte-for-byte.
#
# Step 7 is where a real container replay plugs in: pass a callable that takes a
# TraceEvent and returns the freshly observed output dict. Everything above it
# runs with no network, no Docker and no Ollama.
# =============================================================================

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from evaluation import trace_logger
from evaluation.trace_logger import TraceEvent, load_trace

# ---------------------------------------------------------------------------
# Invalidation reason codes
#
# Every reason string starts with one of these codes so callers (and tests) can
# assert on the code without depending on the human-readable tail.
# ---------------------------------------------------------------------------

REASON_OK = "OK"
REASON_SUMMARY_MISSING = "SUMMARY_MISSING"
REASON_SUMMARY_UNREADABLE = "SUMMARY_UNREADABLE"
REASON_TRACE_FILE_MISSING = "TRACE_FILE_MISSING"
REASON_TRACE_UNREADABLE = "TRACE_UNREADABLE"
REASON_NO_EVENTS = "NO_EVENTS"
REASON_TRACE_ID_MISMATCH = "TRACE_ID_MISMATCH"
REASON_STEP_SEQUENCE_BROKEN = "STEP_SEQUENCE_BROKEN"
REASON_STEP_COUNT_MISMATCH = "STEP_COUNT_MISMATCH"
REASON_TOKEN_MISMATCH = "TOKEN_MISMATCH"
REASON_OUTCOME_INCONSISTENT = "OUTCOME_INCONSISTENT"
REASON_REPLAY_DIVERGENCE = "REPLAY_DIVERGENCE"

# Outcome vocabulary. Red uses AttackOutcome, Blue uses PatchOutcome; both are
# StrEnums whose values land in the summary as plain strings, and finalize() is
# also called with upper-case literals in places — so normalize before comparing.
SUCCESS_OUTCOMES = frozenset({"success", "partial", "patched"})
FAILURE_OUTCOMES = frozenset({"failure", "failed", "timeout", "error"})

# Keys a terminal event may use to restate the engagement outcome.
_TERMINAL_OUTCOME_KEYS = ("outcome", "final_outcome")

# A callable that re-runs one recorded step and returns what it observed.
# Returning None means "this step is not re-executable" and is skipped.
ReexecuteFn = Callable[[TraceEvent], dict | None]


@dataclass(frozen=True)
class ReplayResult:
    """Verdict for one engagement. `valid=False` means INVALIDATED."""

    trace_id: str
    valid: bool
    reason: str

    @property
    def code(self) -> str:
        """The leading reason code, e.g. 'TOKEN_MISMATCH'."""
        return self.reason.split(":", 1)[0].strip()


# ---------------------------------------------------------------------------
# Directory plumbing
# ---------------------------------------------------------------------------


@contextmanager
def _traces_root(traces_dir: Path | str | None):
    """
    Points trace_logger at `traces_dir` for the duration of the block so that
    load_trace() stays the single reader of trace files. Restores the original
    on exit. `None` means "use the repo's evaluation/traces/".
    """
    if traces_dir is None:
        yield Path(trace_logger.TRACES_DIR)
        return

    original = trace_logger.TRACES_DIR
    trace_logger.TRACES_DIR = Path(traces_dir)
    try:
        yield Path(traces_dir)
    finally:
        trace_logger.TRACES_DIR = original


def _canonical(value: object) -> str:
    """Order-independent, type-stable rendering used for output comparison."""
    return json.dumps(value, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Individual checks — each returns an invalidation reason, or None if it passes
# ---------------------------------------------------------------------------


def _check_trace_ids(trace_id: str, events: list[TraceEvent]) -> str | None:
    for event in events:
        if event.trace_id != trace_id:
            return (
                f"{REASON_TRACE_ID_MISMATCH}: step {event.step_number} is filed under "
                f"trace_id={event.trace_id!r}, expected {trace_id!r}"
            )
    return None


def _check_step_sequence(events: list[TraceEvent]) -> str | None:
    for expected, event in enumerate(events, start=1):
        if event.step_number != expected:
            return (
                f"{REASON_STEP_SEQUENCE_BROKEN}: expected step_number {expected} at "
                f"position {expected}, found {event.step_number}"
            )
    return None


def _check_step_count(summary: dict, events: list[TraceEvent]) -> str | None:
    total_steps = summary.get("total_steps")
    if total_steps is None:
        return f"{REASON_STEP_COUNT_MISMATCH}: summary has no total_steps field"
    if total_steps != len(events):
        return (
            f"{REASON_STEP_COUNT_MISMATCH}: summary claims {total_steps} steps, "
            f"trace file holds {len(events)}"
        )
    return None


def _check_tokens(summary: dict, events: list[TraceEvent]) -> str | None:
    total_tokens = summary.get("total_tokens")
    if total_tokens is None:
        return f"{REASON_TOKEN_MISMATCH}: summary has no total_tokens field"
    recorded = sum(event.tokens_used for event in events)
    if total_tokens != recorded:
        return (
            f"{REASON_TOKEN_MISMATCH}: summary claims {total_tokens} tokens, "
            f"events sum to {recorded}"
        )
    return None


def _check_outcome(summary: dict, events: list[TraceEvent]) -> str | None:
    """
    The summary outcome must be present and must not contradict the terminal
    event. A terminal event contradicts the summary when it restates a
    different outcome, or when its `success` flag disagrees with the summary's
    success/failure sense.
    """
    outcome = str(summary.get("outcome") or "").strip()
    if not outcome:
        return f"{REASON_OUTCOME_INCONSISTENT}: summary has no outcome"

    normalized = outcome.lower()
    terminal = events[-1]
    output = terminal.output if isinstance(terminal.output, dict) else {}

    for key in _TERMINAL_OUTCOME_KEYS:
        declared = output.get(key)
        if isinstance(declared, str) and declared.strip().lower() != normalized:
            return (
                f"{REASON_OUTCOME_INCONSISTENT}: summary outcome {outcome!r} but terminal "
                f"step {terminal.step_number} reports {key}={declared!r}"
            )

    success_flag = output.get("success")
    if isinstance(success_flag, bool):
        if success_flag and normalized in FAILURE_OUTCOMES:
            return (
                f"{REASON_OUTCOME_INCONSISTENT}: summary outcome {outcome!r} but terminal "
                f"step {terminal.step_number} reports success=True"
            )
        if not success_flag and normalized in SUCCESS_OUTCOMES:
            return (
                f"{REASON_OUTCOME_INCONSISTENT}: summary outcome {outcome!r} but terminal "
                f"step {terminal.step_number} reports success=False"
            )
    return None


def _check_reexecution(events: list[TraceEvent], reexecute: ReexecuteFn) -> str | None:
    """Re-runs each recorded input and compares against the recorded output."""
    for event in events:
        try:
            observed = reexecute(event)
        except Exception as exc:  # noqa: BLE001 — any failure invalidates the replay
            return (
                f"{REASON_REPLAY_DIVERGENCE}: re-executing step {event.step_number} "
                f"({event.agent}/{event.action}) raised {type(exc).__name__}: {exc}"
            )
        if observed is None:
            continue  # step is not re-executable — not a divergence
        if _canonical(observed) != _canonical(event.output):
            return (
                f"{REASON_REPLAY_DIVERGENCE}: step {event.step_number} "
                f"({event.agent}/{event.action}) replayed to {_canonical(observed)}, "
                f"recorded {_canonical(event.output)}"
            )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_trace(
    trace_id: str,
    reexecute: ReexecuteFn | None = None,
    traces_dir: Path | str | None = None,
) -> ReplayResult:
    """
    Replays one engagement and returns its verdict.

    Args:
        trace_id: the engagement UUID.
        reexecute: optional callable(TraceEvent) -> dict | None that re-runs a
            recorded step. Return None to skip a step. Any mismatch between the
            returned dict and the recorded output invalidates the engagement.
        traces_dir: directory holding {trace_id}.jsonl and {trace_id}_summary.json.
            Defaults to evaluation/traces/.

    Returns:
        ReplayResult — `valid=False` means the engagement is INVALIDATED and its
        reward must not be counted toward ESR/PSR.
    """
    with _traces_root(traces_dir) as root:
        summary_path = root / f"{trace_id}_summary.json"
        if not summary_path.exists():
            return ReplayResult(
                trace_id,
                False,
                f"{REASON_SUMMARY_MISSING}: no summary at {summary_path}",
            )
        try:
            summary = json.loads(summary_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return ReplayResult(
                trace_id,
                False,
                f"{REASON_SUMMARY_UNREADABLE}: {type(exc).__name__}: {exc}",
            )
        if not isinstance(summary, dict):
            return ReplayResult(
                trace_id,
                False,
                f"{REASON_SUMMARY_UNREADABLE}: summary is not a JSON object",
            )

        try:
            events = load_trace(trace_id)
        except FileNotFoundError as exc:
            return ReplayResult(trace_id, False, f"{REASON_TRACE_FILE_MISSING}: {exc}")
        except (OSError, TypeError, ValueError) as exc:
            return ReplayResult(
                trace_id,
                False,
                f"{REASON_TRACE_UNREADABLE}: {type(exc).__name__}: {exc}",
            )

    if not events:
        return ReplayResult(
            trace_id,
            False,
            f"{REASON_NO_EVENTS}: trace file is empty",
        )

    checks = (
        _check_trace_ids(trace_id, events),
        _check_step_sequence(events),
        _check_step_count(summary, events),
        _check_tokens(summary, events),
        _check_outcome(summary, events),
    )
    for reason in checks:
        if reason is not None:
            return ReplayResult(trace_id, False, reason)

    if reexecute is not None:
        reason = _check_reexecution(events, reexecute)
        if reason is not None:
            return ReplayResult(trace_id, False, reason)

    return ReplayResult(
        trace_id,
        True,
        f"{REASON_OK}: {len(events)} steps replayed, outcome={summary.get('outcome')}",
    )


def list_trace_ids(traces_dir: Path | str | None = None) -> list[str]:
    """Every engagement that has a finalized summary, sorted for determinism."""
    with _traces_root(traces_dir) as root:
        if not root.exists():
            return []
        return sorted(path.name[: -len("_summary.json")] for path in root.glob("*_summary.json"))


def verify_all(
    traces_dir: Path | str | None = None,
    reexecute: ReexecuteFn | None = None,
) -> list[ReplayResult]:
    """Replays every finalized engagement. Order is stable (sorted by trace_id)."""
    return [
        verify_trace(trace_id, reexecute=reexecute, traces_dir=traces_dir)
        for trace_id in list_trace_ids(traces_dir)
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def format_report(results: list[ReplayResult]) -> str:
    """Renders the summary table printed by the CLI."""
    header = f"{'TRACE ID':<38} {'VERDICT':<12} REASON"
    lines = [header, "-" * len(header)]
    for result in results:
        verdict = "VALID" if result.valid else "INVALIDATED"
        lines.append(f"{result.trace_id:<38} {verdict:<12} {result.reason}")

    invalid = [r for r in results if not r.valid]
    lines.append("-" * len(header))
    lines.append(
        f"{len(results)} engagement(s): {len(results) - len(invalid)} valid, "
        f"{len(invalid)} invalidated"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Exits non-zero if any engagement is invalidated."""
    parser = argparse.ArgumentParser(
        description="Verify that recorded engagements can be reproduced by trace replay.",
    )
    parser.add_argument(
        "--traces-dir",
        default=None,
        help="Directory of trace files (default: evaluation/traces/).",
    )
    parser.add_argument(
        "--trace-id",
        default=None,
        help="Verify a single engagement instead of all of them.",
    )
    args = parser.parse_args(argv)

    if args.trace_id:
        results = [verify_trace(args.trace_id, traces_dir=args.traces_dir)]
    else:
        results = verify_all(traces_dir=args.traces_dir)

    if not results:
        print("No finalized engagements found — nothing to replay.")
        return 0

    print(format_report(results))
    return 1 if any(not r.valid for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
