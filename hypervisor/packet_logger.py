# =============================================================================
# hypervisor/packet_logger.py
# OWNER: Infra Hire — SECURITY CRITICAL — requires lead + one additional reviewer
# PURPOSE: Captures every byte that crosses the hypervisor bridge between
#          sandbox_agents and sandbox_targets, written to a replayable log.
# =============================================================================
#
# RULE: A successful exploit is only valid if it can be reproduced by replaying
#       the captured packets against a fresh target instance. The packet log is
#       the source of truth consumed by evaluation/replay_harness.py (#27).
#
# FORMAT: newline-delimited JSON (JSONL). One record per captured chunk, written
#         and flushed immediately — never buffered — so a crashed engagement
#         still leaves a replayable, ordered log on disk.
#
# Payload bytes are base64-encoded so arbitrary binary traffic round-trips
# losslessly through JSON.
# =============================================================================

import base64
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from itertools import count
from pathlib import Path
from threading import Lock

from loguru import logger

# Default log location — kept alongside evaluation traces so the replay harness
# and reward functions find packet evidence in one predictable place.
DEFAULT_LOG_DIR = Path(__file__).parent.parent / "evaluation" / "traces"

# Direction labels — fixed strings; replay_harness.py keys off these exactly.
AGENT_TO_TARGET = "agent_to_target"
TARGET_TO_AGENT = "target_to_agent"


@dataclass
class PacketRecord:
    seq: int  # monotonic capture order across the whole engagement
    timestamp: str  # ISO-8601 UTC
    connection_id: str  # groups packets belonging to one bridged TCP connection
    direction: str  # AGENT_TO_TARGET | TARGET_TO_AGENT
    src: str  # "host:port"
    dst: str  # "host:port"
    length: int  # payload length in bytes (pre-encoding)
    data_b64: str  # base64-encoded payload


class PacketLogger:
    """
    Append-only, thread-safe packet capture for a single engagement.

    The bridge holds one PacketLogger and calls log() from every connection
    handler. Writes are serialized with a lock and flushed per record so the
    log stays ordered and replayable even if the process is killed mid-stream.
    """

    def __init__(self, engagement_id: str, log_dir: Path | None = None):
        self.engagement_id = engagement_id
        self._dir = log_dir or DEFAULT_LOG_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / f"{engagement_id}_packets.jsonl"
        self._seq = count()
        self._lock = Lock()
        logger.info(f"[packet] Capturing engagement={engagement_id} -> {self._path}")

    @property
    def path(self) -> Path:
        return self._path

    def log(
        self,
        connection_id: str,
        direction: str,
        src: str,
        dst: str,
        payload: bytes,
    ) -> None:
        """
        Records one captured chunk. Empty payloads are skipped — they carry no
        replay value and would only add noise (e.g. half-close reads).
        """
        if not payload:
            return
        if direction not in (AGENT_TO_TARGET, TARGET_TO_AGENT):
            raise ValueError(f"Unknown packet direction: {direction!r}")

        record = PacketRecord(
            seq=next(self._seq),
            timestamp=datetime.now(UTC).isoformat(),
            connection_id=connection_id,
            direction=direction,
            src=src,
            dst=dst,
            length=len(payload),
            data_b64=base64.b64encode(payload).decode("ascii"),
        )

        line = json.dumps(asdict(record))
        # Serialize writes — multiple connection handlers share one log file.
        with self._lock:
            with open(self._path, "a") as f:
                f.write(line + "\n")
                f.flush()


def load_packets(engagement_id: str, log_dir: Path | None = None) -> list[PacketRecord]:
    """
    Loads all captured packets for an engagement in capture order.
    Used by evaluation/replay_harness.py (#27) to reconstruct the attack.
    """
    directory = log_dir or DEFAULT_LOG_DIR
    path = directory / f"{engagement_id}_packets.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"No packet log for engagement {engagement_id} at {path}")

    records: list[PacketRecord] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(PacketRecord(**json.loads(line)))
    return sorted(records, key=lambda r: r.seq)


def decode_payload(record: PacketRecord) -> bytes:
    """Returns the raw payload bytes for a captured record."""
    return base64.b64decode(record.data_b64)
