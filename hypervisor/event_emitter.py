# =============================================================================
# hypervisor/event_emitter.py
# OWNER: Infra Hire — SECURITY CRITICAL — requires lead + one additional reviewer
# PURPOSE: Emits coordination events from the hypervisor to the Blue Team.
#          The Blue Team pipeline activates ONLY on a confirmed exploit_detected
#          event — never on a timer.
# =============================================================================
#
# EVENT SCHEMA (see hypervisor/README.md — Blue Team Supervisor depends on this):
#
#   EVENT: exploit_detected
#   PAYLOAD: {
#       "cve_id": "CVE-XXXX-XXXX",
#       "target_endpoint": "/vulnerable/path",
#       "attack_goal_achieved": "remote_code_execution",
#       "timestamp": "ISO-8601"
#   }
#
# Events are delivered two ways, both fired by emit_exploit_detected():
#   1. In-process: subscribers registered via subscribe() are called synchronously.
#   2. Cross-process: every event is appended to a JSONL stream on disk so a
#      Blue Team container in a separate process can tail it.
# =============================================================================

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from loguru import logger

EXPLOIT_DETECTED = "exploit_detected"

# Shared stream the Blue Team Supervisor tails for cross-process delivery.
DEFAULT_EVENT_STREAM = Path(__file__).parent.parent / "evaluation" / "traces" / "events.jsonl"


@dataclass
class ExploitDetectedEvent:
    event: str  # always EXPLOIT_DETECTED
    cve_id: str
    target_endpoint: str
    attack_goal_achieved: str
    timestamp: str  # ISO-8601 UTC


Subscriber = Callable[[ExploitDetectedEvent], None]


class EventEmitter:
    """
    Relays CVE-Bench grader confirmations to the Blue Team.

    The bridge / grader integration calls emit_exploit_detected() when the
    CVE-Bench grader confirms an attack goal was achieved. Each event is
    delivered to in-process subscribers and appended to the on-disk stream.
    """

    def __init__(self, event_stream: Path | None = None):
        self._stream = event_stream or DEFAULT_EVENT_STREAM
        self._stream.parent.mkdir(parents=True, exist_ok=True)
        self._subscribers: list[Subscriber] = []
        self._lock = Lock()

    @property
    def stream_path(self) -> Path:
        return self._stream

    def subscribe(self, callback: Subscriber) -> None:
        """Registers an in-process listener (e.g. the Blue Team Supervisor)."""
        self._subscribers.append(callback)

    def emit_exploit_detected(
        self,
        cve_id: str,
        target_endpoint: str,
        attack_goal_achieved: str,
    ) -> ExploitDetectedEvent:
        """
        Fires an exploit_detected event. Called only after the CVE-Bench grader
        CONFIRMS the goal — this is what activates the Blue Team pipeline.

        Returns the emitted event so callers can correlate it with a trace.
        """
        event = ExploitDetectedEvent(
            event=EXPLOIT_DETECTED,
            cve_id=cve_id,
            target_endpoint=target_endpoint,
            attack_goal_achieved=attack_goal_achieved,
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Persist first (crash safety) — a confirmed exploit must never be lost.
        line = json.dumps(asdict(event))
        with self._lock:
            with open(self._stream, "a") as f:
                f.write(line + "\n")
                f.flush()

        logger.warning(
            f"[event] exploit_detected cve={cve_id} endpoint={target_endpoint} "
            f"goal={attack_goal_achieved}"
        )

        # Then notify in-process subscribers. A misbehaving subscriber must not
        # prevent the others from receiving the event.
        for callback in self._subscribers:
            try:
                callback(event)
            except Exception as exc:  # noqa: BLE001 — isolate subscriber failures
                logger.error(f"[event] Subscriber {callback!r} raised: {exc}")

        return event


def load_events(event_stream: Path | None = None) -> list[ExploitDetectedEvent]:
    """Loads all emitted events in order — used in tests and post-run analysis."""
    stream = event_stream or DEFAULT_EVENT_STREAM
    if not stream.exists():
        return []

    events: list[ExploitDetectedEvent] = []
    with open(stream) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(ExploitDetectedEvent(**json.loads(line)))
    return events
