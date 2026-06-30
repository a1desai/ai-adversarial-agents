# =============================================================================
# tests/unit/test_hypervisor.py
# OWNER: Infra Hire
# MARKERS: unit (no Docker — uses loopback TCP sockets and a tmp log dir)
# PURPOSE: Tests for the hypervisor layer (#33):
#            - packet_logger:  capture is ordered, replayable, lossless
#            - event_emitter:  exploit_detected schema + in-proc/on-disk delivery
#            - bridge:         end-to-end relay over loopback, every byte logged
# RUN: pytest tests/unit/test_hypervisor.py -v
# =============================================================================

import asyncio

import pytest

from hypervisor.bridge import HypervisorBridge, Route, _parse_route
from hypervisor.event_emitter import EXPLOIT_DETECTED, EventEmitter, load_events
from hypervisor.packet_logger import (
    AGENT_TO_TARGET,
    TARGET_TO_AGENT,
    PacketLogger,
    decode_payload,
    load_packets,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# packet_logger
# ---------------------------------------------------------------------------


def test_packet_log_is_ordered_and_replayable(tmp_path):
    logger = PacketLogger("eng-1", log_dir=tmp_path)
    logger.log("c1", AGENT_TO_TARGET, "agent:5000", "target:80", b"GET / HTTP/1.1\r\n")
    logger.log("c1", TARGET_TO_AGENT, "target:80", "agent:5000", b"HTTP/1.1 200 OK\r\n")

    records = load_packets("eng-1", log_dir=tmp_path)
    assert [r.seq for r in records] == [0, 1]
    assert records[0].direction == AGENT_TO_TARGET
    assert decode_payload(records[0]) == b"GET / HTTP/1.1\r\n"
    assert records[1].direction == TARGET_TO_AGENT
    assert decode_payload(records[1]) == b"HTTP/1.1 200 OK\r\n"


def test_packet_log_round_trips_binary(tmp_path):
    payload = bytes(range(256))
    logger = PacketLogger("eng-bin", log_dir=tmp_path)
    logger.log("c1", AGENT_TO_TARGET, "a", "b", payload)
    assert decode_payload(load_packets("eng-bin", log_dir=tmp_path)[0]) == payload


def test_packet_logger_skips_empty_and_rejects_bad_direction(tmp_path):
    logger = PacketLogger("eng-2", log_dir=tmp_path)
    logger.log("c1", AGENT_TO_TARGET, "a", "b", b"")  # skipped — no replay value
    assert not logger.path.exists() or logger.path.read_text() == ""
    with pytest.raises(ValueError):
        logger.log("c1", "sideways", "a", "b", b"data")


def test_load_packets_missing_engagement_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_packets("nope", log_dir=tmp_path)


# ---------------------------------------------------------------------------
# event_emitter
# ---------------------------------------------------------------------------


def test_emit_exploit_detected_schema_and_delivery(tmp_path):
    stream = tmp_path / "events.jsonl"
    emitter = EventEmitter(event_stream=stream)

    received = []
    emitter.subscribe(received.append)

    event = emitter.emit_exploit_detected(
        cve_id="CVE-2024-1001",
        target_endpoint="/vulnerable/path",
        attack_goal_achieved="remote_code_execution",
    )

    # README schema — Blue Team Supervisor depends on these exact fields.
    assert event.event == EXPLOIT_DETECTED
    assert event.cve_id == "CVE-2024-1001"
    assert event.target_endpoint == "/vulnerable/path"
    assert event.attack_goal_achieved == "remote_code_execution"
    assert event.timestamp.endswith("+00:00")

    # In-process subscriber fired...
    assert received == [event]
    # ...and the event persisted for cross-process consumers.
    assert load_events(stream) == [event]


def test_subscriber_exception_does_not_block_others(tmp_path):
    emitter = EventEmitter(event_stream=tmp_path / "events.jsonl")
    seen = []
    emitter.subscribe(lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    emitter.subscribe(seen.append)

    emitter.emit_exploit_detected("CVE-X", "/x", "rce")
    assert len(seen) == 1  # second subscriber still got it


# ---------------------------------------------------------------------------
# bridge — end-to-end over loopback
# ---------------------------------------------------------------------------


async def _echo_server():
    """A stand-in 'target' that upper-cases whatever it receives, then closes."""

    async def handle(reader, writer):
        data = await reader.read(1024)
        writer.write(data.upper())
        await writer.drain()
        writer.write_eof()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_bridge_relays_and_logs_every_byte(tmp_path):
    target_server, target_port = await _echo_server()

    packet_logger = PacketLogger("eng-bridge", log_dir=tmp_path)
    bridge = HypervisorBridge(
        routes=[Route("127.0.0.1", 0, "127.0.0.1", target_port)],
        packet_logger=packet_logger,
    )
    await bridge.start()
    listen_port = bridge._servers[0].sockets[0].getsockname()[1]

    # Agent connects to the bridge (NOT the target) and sends a request.
    reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
    writer.write(b"attack-payload")
    await writer.drain()
    writer.write_eof()
    response = await reader.read(1024)
    writer.close()

    # Relay worked through the bridge: echo target upper-cased the payload.
    assert response == b"ATTACK-PAYLOAD"

    await bridge.stop()
    target_server.close()
    await target_server.wait_closed()

    # Both directions were captured verbatim — invariant: nothing relayed unlogged.
    records = load_packets("eng-bridge", log_dir=tmp_path)
    by_dir = {r.direction: decode_payload(r) for r in records}
    assert by_dir[AGENT_TO_TARGET] == b"attack-payload"
    assert by_dir[TARGET_TO_AGENT] == b"ATTACK-PAYLOAD"


# ---------------------------------------------------------------------------
# bridge — config parsing / guards
# ---------------------------------------------------------------------------


def test_parse_route_valid():
    route = _parse_route("0.0.0.0:8080:172.20.0.5:80")
    assert route == Route("0.0.0.0", 8080, "172.20.0.5", 80)


def test_parse_route_rejects_malformed():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        _parse_route("0.0.0.0:8080:172.20.0.5")  # missing target port


def test_bridge_requires_at_least_one_route(tmp_path):
    with pytest.raises(ValueError):
        HypervisorBridge(routes=[], packet_logger=PacketLogger("e", log_dir=tmp_path))
