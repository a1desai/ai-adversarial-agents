# =============================================================================
# hypervisor/bridge.py
# OWNER: Infra Hire — SECURITY CRITICAL — requires lead + one additional reviewer
# PURPOSE: The network bridge between sandbox_agents and sandbox_targets.
#          This is the ONLY path from agents to targets. A bypass here breaks
#          the entire sandbox guarantee.
# =============================================================================
#
# DESIGN: A TCP-level forwarding proxy. The bridge container sits on all three
#         networks (sandbox_agents, sandbox_hypervisor, sandbox_targets — see
#         docker-compose.agents.yml). The agent networks are `internal: true`
#         (docker-compose.yml), so agents have NO route to targets except by
#         connecting to a bridge listener.
#
#         For each configured route, the bridge listens on a port reachable from
#         the agent network and forwards every connection to the matching target
#         on the target network. Every byte in both directions is captured by
#         PacketLogger before being relayed, producing the replayable evidence
#         log consumed by evaluation/replay_harness.py (#27).
#
# SECURITY INVARIANTS (enforced here — not by convention):
#   1. Agents reach targets ONLY through a configured Route. There is no
#      catch-all / dynamic-destination path — an agent cannot ask the bridge to
#      connect somewhere arbitrary.
#   2. Every relayed chunk is logged BEFORE it is forwarded. No silent passthrough.
# =============================================================================

import argparse
import asyncio
import contextlib
from dataclasses import dataclass

from loguru import logger

from hypervisor.event_emitter import EventEmitter
from hypervisor.packet_logger import AGENT_TO_TARGET, TARGET_TO_AGENT, PacketLogger

# Bytes read per relay iteration. Large enough to keep throughput up, small
# enough that the packet log stays granular for replay.
_CHUNK = 65536


@dataclass(frozen=True)
class Route:
    """A single agent-facing listener forwarded to one fixed target endpoint."""

    listen_host: str
    listen_port: int
    target_host: str
    target_port: int

    def __str__(self) -> str:
        return f"{self.listen_host}:{self.listen_port} -> {self.target_host}:{self.target_port}"


class HypervisorBridge:
    """
    Forwarding bridge between the agent and target networks.

    Construct with the set of allowed routes, then `await start()` and
    `await serve_forever()`. Each accepted connection is proxied to its route's
    fixed target; nothing else is reachable.
    """

    def __init__(
        self,
        routes: list[Route],
        packet_logger: PacketLogger,
        event_emitter: EventEmitter | None = None,
    ):
        if not routes:
            raise ValueError("HypervisorBridge requires at least one route")
        self._routes = routes
        self._packets = packet_logger
        self._events = event_emitter or EventEmitter()
        self._servers: list[asyncio.base_events.Server] = []
        self._conn_seq = 0

    @property
    def events(self) -> EventEmitter:
        """The event emitter — exposed so the grader integration can fire events."""
        return self._events

    def _next_connection_id(self) -> str:
        self._conn_seq += 1
        return f"{self._packets.engagement_id}-conn-{self._conn_seq}"

    async def start(self) -> None:
        """Binds a listener for every configured route."""
        for route in self._routes:
            server = await asyncio.start_server(
                self._make_handler(route),
                host=route.listen_host,
                port=route.listen_port,
            )
            self._servers.append(server)
            logger.info(f"[bridge] Listening {route}")

    async def serve_forever(self) -> None:
        """Serves all listeners until cancelled."""
        await asyncio.gather(*(s.serve_forever() for s in self._servers))

    async def stop(self) -> None:
        """Closes all listeners and waits for them to release their sockets."""
        for server in self._servers:
            server.close()
        for server in self._servers:
            await server.wait_closed()
        self._servers.clear()
        logger.info("[bridge] Stopped")

    def _make_handler(self, route: Route):
        async def handler(
            agent_reader: asyncio.StreamReader,
            agent_writer: asyncio.StreamWriter,
        ) -> None:
            await self._handle_connection(route, agent_reader, agent_writer)

        return handler

    async def _handle_connection(
        self,
        route: Route,
        agent_reader: asyncio.StreamReader,
        agent_writer: asyncio.StreamWriter,
    ) -> None:
        connection_id = self._next_connection_id()
        agent_peer = _peername(agent_writer)
        target_peer = f"{route.target_host}:{route.target_port}"
        logger.debug(f"[bridge] {connection_id} open {agent_peer} <-> {target_peer}")

        # Connect to the route's FIXED target. The destination is never taken
        # from anything the agent sends — invariant #1.
        try:
            target_reader, target_writer = await asyncio.open_connection(
                route.target_host, route.target_port
            )
        except OSError as exc:
            logger.error(f"[bridge] {connection_id} target unreachable {target_peer}: {exc}")
            agent_writer.close()
            return

        try:
            await asyncio.gather(
                self._pump(
                    connection_id,
                    AGENT_TO_TARGET,
                    src=agent_peer,
                    dst=target_peer,
                    reader=agent_reader,
                    writer=target_writer,
                ),
                self._pump(
                    connection_id,
                    TARGET_TO_AGENT,
                    src=target_peer,
                    dst=agent_peer,
                    reader=target_reader,
                    writer=agent_writer,
                ),
            )
        finally:
            for writer in (agent_writer, target_writer):
                writer.close()
            logger.debug(f"[bridge] {connection_id} closed")

    async def _pump(
        self,
        connection_id: str,
        direction: str,
        *,
        src: str,
        dst: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Relays one direction of a connection, logging every chunk BEFORE it is
        forwarded (invariant #2). Half-closes the peer when the source ends.
        """
        try:
            while not reader.at_eof():
                chunk = await reader.read(_CHUNK)
                if not chunk:
                    break
                # Log first — no byte reaches the target/agent unrecorded.
                self._packets.log(connection_id, direction, src, dst, chunk)
                writer.write(chunk)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError) as exc:
            logger.debug(f"[bridge] {connection_id} {direction} reset: {exc}")
        finally:
            # Propagate the half-close so the other end sees the stream finish.
            if writer.can_write_eof():
                with contextlib.suppress(OSError):
                    writer.write_eof()


def _peername(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer)


# ---------------------------------------------------------------------------
# CLI entry point — runs the bridge as the hypervisor container's main process
# ---------------------------------------------------------------------------


def _parse_route(spec: str) -> Route:
    """Parses 'listen_host:listen_port:target_host:target_port'."""
    parts = spec.split(":")
    if len(parts) != 4:
        raise argparse.ArgumentTypeError(
            f"Route must be listen_host:listen_port:target_host:target_port, got {spec!r}"
        )
    listen_host, listen_port, target_host, target_port = parts
    return Route(listen_host, int(listen_port), target_host, int(target_port))


async def _main(args: argparse.Namespace) -> None:
    routes = [_parse_route(spec) for spec in args.route]
    packet_logger = PacketLogger(engagement_id=args.engagement_id)
    bridge = HypervisorBridge(routes, packet_logger)
    await bridge.start()
    logger.info(f"[bridge] Engagement {args.engagement_id} — {len(routes)} route(s) up")
    try:
        await bridge.serve_forever()
    except asyncio.CancelledError:
        await bridge.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sandbox hypervisor bridge")
    parser.add_argument(
        "--engagement-id",
        required=True,
        help="Identifier grouping this run's packet log and events",
    )
    parser.add_argument(
        "--route",
        action="append",
        required=True,
        metavar="L_HOST:L_PORT:T_HOST:T_PORT",
        help="Agent-facing listener forwarded to a fixed target (repeatable)",
    )
    asyncio.run(_main(parser.parse_args()))
