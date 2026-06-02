# =============================================================================
# tests/unit/test_trace_logger.py
# OWNER: Eval Hire
# MARKERS: unit
# PURPOSE: Tests for evaluation/trace_logger.py
# RUN: pytest tests/unit/test_trace_logger.py -v
# =============================================================================

import json
from unittest.mock import patch

import pytest

from evaluation.trace_logger import TraceLogger, load_trace


class TestTraceLogger:
    @pytest.fixture
    def temp_traces_dir(self, tmp_path):
        """Use a temp directory for traces so tests don't pollute evaluation/traces/."""
        with patch("evaluation.trace_logger.TRACES_DIR", tmp_path):
            yield tmp_path

    def test_new_logger_gets_unique_trace_id(self, temp_traces_dir):
        logger1 = TraceLogger(team="red", target_cve="CVE-2024-1001")
        logger2 = TraceLogger(team="red", target_cve="CVE-2024-1001")
        assert logger1.trace_id != logger2.trace_id

    def test_log_writes_to_disk_immediately(self, temp_traces_dir):
        logger = TraceLogger(team="red", target_cve="CVE-2024-1001")
        logger.log(
            agent="recon_agent",
            action="nmap_scan",
            input_data={"target": "localhost"},
            output_data={"ports": [80, 443]},
            tokens_used=150,
        )
        trace_file = temp_traces_dir / f"{logger.trace_id}.jsonl"
        assert trace_file.exists()
        lines = trace_file.read_text().strip().split("\n")
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["agent"] == "recon_agent"
        assert event["tokens_used"] == 150

    def test_step_count_increments(self, temp_traces_dir):
        logger = TraceLogger(team="red", target_cve="CVE-2024-1001")
        logger.log("agent1", "action1", {}, {})
        logger.log("agent2", "action2", {}, {})
        logger.log("agent3", "action3", {}, {})
        assert logger.events[2].step_number == 3

    def test_finalize_writes_summary(self, temp_traces_dir):
        logger = TraceLogger(team="blue", target_cve="CVE-2024-1002")
        logger.log("patch_agent", "patch_deployed", {}, {"result": "success"})
        logger.finalize(outcome="SUCCESS", notes="patch blocked exploit")

        summary_file = temp_traces_dir / f"{logger.trace_id}_summary.json"
        assert summary_file.exists()
        data = json.loads(summary_file.read_text())
        assert data["outcome"] == "SUCCESS"
        assert data["team"] == "blue"

    def test_load_trace_returns_all_events(self, temp_traces_dir):
        logger = TraceLogger(team="red", target_cve="CVE-2024-1003")
        for i in range(5):
            logger.log(f"agent_{i}", f"action_{i}", {}, {}, tokens_used=i * 10)

        events = load_trace(logger.trace_id)
        assert len(events) == 5
        assert events[4].step_number == 5

    def test_load_nonexistent_trace_raises(self, temp_traces_dir):
        with pytest.raises(FileNotFoundError):
            load_trace("nonexistent-trace-id")
