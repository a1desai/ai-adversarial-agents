# =============================================================================
# evaluation/trace_logger.py
# OWNER: Eval Hire
# PURPOSE: Deterministic trace logging for all agent engagements.
#          Every action is recorded with a UUID trace ID and can be replayed.
# =============================================================================
#
# RULE: A successful exploit or patch is only valid if it can be reproduced
#       by replaying the trace against a fresh container instance.
#       If replay fails, the original result is invalidated.
# =============================================================================

import uuid
import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from loguru import logger


TRACES_DIR = Path(__file__).parent / "traces"
TRACES_DIR.mkdir(exist_ok=True)


@dataclass
class TraceEvent:
    trace_id:   str
    timestamp:  str
    team:       str           # "red" or "blue"
    agent:      str           # e.g. "exploitation_agent"
    action:     str           # e.g. "payload_executed"
    input:      dict
    output:     dict
    tokens_used: int
    step_number: int


class TraceLogger:
    """
    Records all agent actions for a single engagement.
    One TraceLogger per engagement (trace_id).
    """

    def __init__(self, team: str, target_cve: str):
        self.trace_id  = str(uuid.uuid4())
        self.team      = team
        self.target_cve = target_cve
        self.events:   list[TraceEvent] = []
        self._step     = 0
        self._path     = TRACES_DIR / f"{self.trace_id}.jsonl"
        logger.info(f"[trace] New engagement: trace_id={self.trace_id} cve={target_cve}")

    def log(
        self,
        agent:       str,
        action:      str,
        input_data:  dict,
        output_data: dict,
        tokens_used: int = 0,
    ):
        """Records a single agent action. Call this after every agent step."""
        self._step += 1
        event = TraceEvent(
            trace_id    = self.trace_id,
            timestamp   = datetime.now(timezone.utc).isoformat(),
            team        = self.team,
            agent       = agent,
            action      = action,
            input       = input_data,
            output      = output_data,
            tokens_used = tokens_used,
            step_number = self._step,
        )
        self.events.append(event)

        # Append to JSONL file immediately (don't buffer — crash safety)
        with open(self._path, "a") as f:
            f.write(json.dumps(asdict(event)) + "\n")

    def finalize(self, outcome: str, notes: str = ""):
        """
        Writes a final summary record. Call at end of engagement.
        """
        summary = {
            "trace_id":    self.trace_id,
            "team":        self.team,
            "target_cve":  self.target_cve,
            "outcome":     outcome,
            "total_steps": self._step,
            "total_tokens": sum(e.tokens_used for e in self.events),
            "notes":       notes,
            "events_file": str(self._path),
        }
        summary_path = TRACES_DIR / f"{self.trace_id}_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(
            f"[trace] Engagement complete: trace_id={self.trace_id} "
            f"outcome={outcome} steps={self._step}"
        )
        return summary


def load_trace(trace_id: str) -> list[TraceEvent]:
    """Loads all events for a trace ID from disk."""
    path = TRACES_DIR / f"{trace_id}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"Trace {trace_id} not found at {path}")

    events = []
    with open(path) as f:
        for line in f:
            data = json.loads(line)
            events.append(TraceEvent(**data))
    return events


def list_traces(team: str | None = None, outcome: str | None = None) -> list[dict]:
    """
    Lists all completed trace summaries, optionally filtered by team or outcome.
    """
    summaries = []
    for summary_file in TRACES_DIR.glob("*_summary.json"):
        with open(summary_file) as f:
            summary = json.load(f)
        if team and summary.get("team") != team:
            continue
        if outcome and summary.get("outcome") != outcome:
            continue
        summaries.append(summary)

    return sorted(summaries, key=lambda x: x.get("trace_id", ""))