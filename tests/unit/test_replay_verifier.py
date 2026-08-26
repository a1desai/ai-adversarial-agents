# =============================================================================
# tests/unit/test_replay_verifier.py
# OWNER: Eval Hire
# MARKERS: unit
# PURPOSE: Tests for evaluation/replay_verifier.py — proves that a consistent
#          trace replays clean and that every flavour of divergence gets the
#          engagement INVALIDATED with the right reason code.
# RUN: pytest tests/unit/test_replay_verifier.py -v
# =============================================================================
#
# NOTE: AI-assisted (drafted with Claude), human-reviewed.
# =============================================================================

import json
from dataclasses import asdict

import pytest

from evaluation.replay_verifier import (
    REASON_NO_EVENTS,
    REASON_OK,
    REASON_OUTCOME_INCONSISTENT,
    REASON_REPLAY_DIVERGENCE,
    REASON_STEP_COUNT_MISMATCH,
    REASON_STEP_SEQUENCE_BROKEN,
    REASON_SUMMARY_MISSING,
    REASON_TOKEN_MISMATCH,
    REASON_TRACE_FILE_MISSING,
    REASON_TRACE_ID_MISMATCH,
    ReplayResult,
    format_report,
    list_trace_ids,
    main,
    verify_all,
    verify_trace,
)
from evaluation.trace_logger import TraceEvent

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Synthetic trace builders — no Ollama, no Docker, no live containers.
# ---------------------------------------------------------------------------


def make_event(
    trace_id: str,
    step_number: int,
    *,
    tokens_used: int = 100,
    agent: str = "exploitation_agent",
    action: str = "payload_executed",
    output: dict | None = None,
) -> TraceEvent:
    return TraceEvent(
        trace_id=trace_id,
        timestamp=f"2026-08-25T12:00:{step_number:02d}+00:00",
        team="red",
        agent=agent,
        action=action,
        input={"payload": f"payload-{step_number}"},
        output=output if output is not None else {"status": 200, "step": step_number},
        tokens_used=tokens_used,
        step_number=step_number,
    )


def write_trace(
    traces_dir,
    trace_id: str,
    events: list[TraceEvent],
    *,
    outcome: str = "success",
    total_steps: int | None = None,
    total_tokens: int | None = None,
    write_summary: bool = True,
    write_events: bool = True,
) -> str:
    """Writes {trace_id}.jsonl (+ summary) exactly as TraceLogger would."""
    if write_events:
        jsonl = traces_dir / f"{trace_id}.jsonl"
        jsonl.write_text("".join(json.dumps(asdict(e)) + "\n" for e in events))

    if write_summary:
        summary = {
            "trace_id": trace_id,
            "team": "red",
            "target_cve": "CVE-2024-1001",
            "outcome": outcome,
            "total_steps": len(events) if total_steps is None else total_steps,
            "total_tokens": (
                sum(e.tokens_used for e in events) if total_tokens is None else total_tokens
            ),
            "notes": "",
            "events_file": str(traces_dir / f"{trace_id}.jsonl"),
        }
        (traces_dir / f"{trace_id}_summary.json").write_text(json.dumps(summary, indent=2))

    return trace_id


@pytest.fixture
def traces_dir(tmp_path):
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture
def good_trace(traces_dir):
    """A well-formed, internally consistent 3-step engagement."""
    trace_id = "11111111-1111-4111-8111-111111111111"
    events = [make_event(trace_id, i, tokens_used=i * 10) for i in (1, 2, 3)]
    write_trace(traces_dir, trace_id, events)
    return trace_id


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestConsistentTracePasses:
    def test_wellformed_trace_is_valid(self, traces_dir, good_trace):
        result = verify_trace(good_trace, traces_dir=traces_dir)
        assert isinstance(result, ReplayResult)
        assert result.valid is True
        assert result.code == REASON_OK
        assert result.trace_id == good_trace

    def test_single_step_trace_is_valid(self, traces_dir):
        trace_id = "22222222-2222-4222-8222-222222222222"
        write_trace(traces_dir, trace_id, [make_event(trace_id, 1)])
        assert verify_trace(trace_id, traces_dir=traces_dir).valid is True

    def test_reexecute_reproducing_outputs_is_valid(self, traces_dir, good_trace):
        calls = []

        def reexecute(event: TraceEvent) -> dict:
            calls.append(event.step_number)
            return dict(event.output)  # perfect reproduction

        result = verify_trace(good_trace, reexecute=reexecute, traces_dir=traces_dir)
        assert result.valid is True
        assert calls == [1, 2, 3]

    def test_reexecute_returning_none_skips_the_step(self, traces_dir, good_trace):
        result = verify_trace(good_trace, reexecute=lambda event: None, traces_dir=traces_dir)
        assert result.valid is True

    def test_key_order_does_not_matter_for_reexecution(self, traces_dir):
        trace_id = "33333333-3333-4333-8333-333333333333"
        event = make_event(trace_id, 1, output={"status": 200, "body": "flag{x}"})
        write_trace(traces_dir, trace_id, [event])

        def reexecute(ev: TraceEvent) -> dict:
            return {"body": "flag{x}", "status": 200}  # same content, other order

        assert verify_trace(trace_id, reexecute=reexecute, traces_dir=traces_dir).valid is True


# ---------------------------------------------------------------------------
# Divergence → INVALIDATED
# ---------------------------------------------------------------------------


class TestDivergenceInvalidates:
    def test_token_mismatch_is_invalidated(self, traces_dir):
        trace_id = "44444444-4444-4444-8444-444444444444"
        events = [make_event(trace_id, i, tokens_used=100) for i in (1, 2)]
        write_trace(traces_dir, trace_id, events, total_tokens=9999)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_TOKEN_MISMATCH
        assert "9999" in result.reason and "200" in result.reason

    def test_step_gap_is_invalidated(self, traces_dir):
        trace_id = "55555555-5555-4555-8555-555555555555"
        # step_numbers 1, 2, 4 — step 3 is missing
        events = [make_event(trace_id, i) for i in (1, 2, 4)]
        write_trace(traces_dir, trace_id, events)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_STEP_SEQUENCE_BROKEN

    def test_non_monotonic_steps_are_invalidated(self, traces_dir):
        trace_id = "66666666-6666-4666-8666-666666666666"
        events = [make_event(trace_id, i) for i in (1, 3, 2)]
        write_trace(traces_dir, trace_id, events)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_STEP_SEQUENCE_BROKEN

    def test_steps_not_starting_at_one_are_invalidated(self, traces_dir):
        trace_id = "77777777-7777-4777-8777-777777777777"
        events = [make_event(trace_id, i) for i in (2, 3)]
        write_trace(traces_dir, trace_id, events)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_STEP_SEQUENCE_BROKEN

    def test_wrong_trace_id_on_an_event_is_invalidated(self, traces_dir):
        trace_id = "88888888-8888-4888-8888-888888888888"
        events = [make_event(trace_id, 1), make_event("some-other-trace", 2)]
        write_trace(traces_dir, trace_id, events)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_TRACE_ID_MISMATCH
        assert "some-other-trace" in result.reason

    def test_step_count_mismatch_is_invalidated(self, traces_dir):
        trace_id = "99999999-9999-4999-8999-999999999999"
        events = [make_event(trace_id, i, tokens_used=0) for i in (1, 2)]
        write_trace(traces_dir, trace_id, events, total_steps=7)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_STEP_COUNT_MISMATCH

    def test_reexecute_divergence_is_invalidated(self, traces_dir, good_trace):
        def reexecute(event: TraceEvent) -> dict:
            if event.step_number == 2:
                return {"status": 500, "step": 2}  # container no longer reproduces it
            return dict(event.output)

        result = verify_trace(good_trace, reexecute=reexecute, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_REPLAY_DIVERGENCE
        assert "step 2" in result.reason

    def test_reexecute_raising_is_invalidated(self, traces_dir, good_trace):
        def reexecute(event: TraceEvent) -> dict:
            raise RuntimeError("container unreachable")

        result = verify_trace(good_trace, reexecute=reexecute, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_REPLAY_DIVERGENCE
        assert "RuntimeError" in result.reason

    def test_outcome_contradicting_terminal_event_is_invalidated(self, traces_dir):
        trace_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        events = [
            make_event(trace_id, 1),
            make_event(trace_id, 2, output={"outcome": "failure", "success": False}),
        ]
        write_trace(traces_dir, trace_id, events, outcome="success")

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_OUTCOME_INCONSISTENT

    def test_success_flag_contradicting_outcome_is_invalidated(self, traces_dir):
        trace_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        events = [make_event(trace_id, 1, output={"success": False})]
        write_trace(traces_dir, trace_id, events, outcome="SUCCESS")

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_OUTCOME_INCONSISTENT

    def test_terminal_outcome_matching_summary_case_insensitively_is_valid(self, traces_dir):
        trace_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        events = [make_event(trace_id, 1, output={"outcome": "SUCCESS", "success": True})]
        write_trace(traces_dir, trace_id, events, outcome="success")

        assert verify_trace(trace_id, traces_dir=traces_dir).valid is True

    def test_empty_outcome_is_invalidated(self, traces_dir):
        trace_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        write_trace(traces_dir, trace_id, [make_event(trace_id, 1)], outcome="")

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_OUTCOME_INCONSISTENT


# ---------------------------------------------------------------------------
# Missing / unreadable artifacts
# ---------------------------------------------------------------------------


class TestMissingArtifacts:
    def test_missing_summary_is_invalidated(self, traces_dir):
        trace_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        write_trace(traces_dir, trace_id, [make_event(trace_id, 1)], write_summary=False)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_SUMMARY_MISSING

    def test_missing_trace_file_is_invalidated(self, traces_dir):
        trace_id = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        write_trace(traces_dir, trace_id, [make_event(trace_id, 1)], write_events=False)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_TRACE_FILE_MISSING

    def test_empty_trace_file_is_invalidated(self, traces_dir):
        trace_id = "12121212-1212-4121-8121-121212121212"
        write_trace(traces_dir, trace_id, [], total_steps=0, total_tokens=0)

        result = verify_trace(trace_id, traces_dir=traces_dir)
        assert result.valid is False
        assert result.code == REASON_NO_EVENTS


# ---------------------------------------------------------------------------
# verify_all + CLI
# ---------------------------------------------------------------------------


class TestVerifyAll:
    @pytest.fixture
    def mixed_traces(self, traces_dir):
        ok_id = "0000aaaa-0000-4000-8000-000000000001"
        bad_id = "0000bbbb-0000-4000-8000-000000000002"
        write_trace(traces_dir, ok_id, [make_event(ok_id, i) for i in (1, 2)])
        write_trace(traces_dir, bad_id, [make_event(bad_id, 1)], total_tokens=42)
        return ok_id, bad_id

    def test_list_trace_ids_enumerates_summaries(self, traces_dir, mixed_traces):
        ok_id, bad_id = mixed_traces
        assert list_trace_ids(traces_dir) == sorted([ok_id, bad_id])

    def test_list_trace_ids_on_missing_dir_is_empty(self, tmp_path):
        assert list_trace_ids(tmp_path / "does-not-exist") == []

    def test_verify_all_returns_one_result_per_engagement(self, traces_dir, mixed_traces):
        ok_id, bad_id = mixed_traces
        results = verify_all(traces_dir=traces_dir)
        assert [r.trace_id for r in results] == sorted([ok_id, bad_id])

        by_id = {r.trace_id: r for r in results}
        assert by_id[ok_id].valid is True
        assert by_id[bad_id].valid is False
        assert by_id[bad_id].code == REASON_TOKEN_MISMATCH

    def test_verify_all_threads_reexecute_through(self, traces_dir, mixed_traces):
        ok_id, _ = mixed_traces
        results = verify_all(traces_dir=traces_dir, reexecute=lambda ev: {"nope": True})
        by_id = {r.trace_id: r for r in results}
        assert by_id[ok_id].valid is False
        assert by_id[ok_id].code == REASON_REPLAY_DIVERGENCE

    def test_verify_all_on_empty_dir(self, traces_dir):
        assert verify_all(traces_dir=traces_dir) == []

    def test_traces_dir_default_is_not_mutated(self, traces_dir, good_trace):
        from evaluation import trace_logger

        original = trace_logger.TRACES_DIR
        verify_trace(good_trace, traces_dir=traces_dir)
        assert original == trace_logger.TRACES_DIR


class TestCli:
    def test_cli_exits_zero_when_all_valid(self, traces_dir, good_trace, capsys):
        code = main(["--traces-dir", str(traces_dir)])
        out = capsys.readouterr().out
        assert code == 0
        assert good_trace in out
        assert "VALID" in out

    def test_cli_exits_nonzero_when_any_invalidated(self, traces_dir, capsys):
        trace_id = "13131313-1313-4131-8131-131313131313"
        write_trace(traces_dir, trace_id, [make_event(trace_id, 1)], total_tokens=1)

        code = main(["--traces-dir", str(traces_dir)])
        out = capsys.readouterr().out
        assert code == 1
        assert "INVALIDATED" in out
        assert REASON_TOKEN_MISMATCH in out

    def test_cli_single_trace_id(self, traces_dir, good_trace, capsys):
        code = main(["--traces-dir", str(traces_dir), "--trace-id", good_trace])
        assert code == 0
        assert good_trace in capsys.readouterr().out

    def test_cli_on_empty_dir_exits_zero(self, traces_dir, capsys):
        code = main(["--traces-dir", str(traces_dir)])
        assert code == 0
        assert "nothing to replay" in capsys.readouterr().out

    def test_format_report_counts_both_buckets(self):
        report = format_report(
            [
                ReplayResult("trace-a", True, "OK: 2 steps replayed"),
                ReplayResult("trace-b", False, "TOKEN_MISMATCH: nope"),
            ]
        )
        assert "2 engagement(s): 1 valid, 1 invalidated" in report
