# ADR-0007: Docker-compose three-stack network isolation

- **Status:** Accepted
- **Date:** 2026-08-25
- **Reference:** `docs/red_team_report.md` §8.2–8.3; `docs/blue_team_report.md` §8.2–8.3

<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

## Context

The system deliberately runs live exploits against vulnerable applications. That work is
only safe if a successful exploit — or even a container escape — cannot reach the host or
the wider network. The deployment must therefore isolate the intentionally-vulnerable
targets from both the agent infrastructure and the outside world, while still allowing
the agents to attack the targets and log everything, all using free, open-source
components.

## Decision

Deploy as **three Docker Compose stacks**:

1. **Target stack** — the CVE-Bench target containers on an isolated Docker network with
   **no external access**.
2. **Agent-infrastructure stack** — the Ollama server, the ChromaDB-in-process Python
   agents (ADR-0002), and the LangGraph execution engine (ADR-0003).
3. **Sandbox hypervisor** — the only bridge between the agent network and the target
   network; it enforces firewall rules and **logs every packet**.

All inter-stack traffic flows through the hypervisor. Target containers run hardened:
`--cap-drop=ALL`, read-only root filesystems where possible, CPU/memory cgroup limits,
and no access to the Docker socket. The host firewall blocks all outbound traffic from
the target network — an air-gapped design.

## Consequences

- **Contained blast radius:** even a successful container escape cannot compromise the
  host or reach external networks.
- **Full observability:** routing every packet through the hypervisor yields a complete,
  auditable record of agent–target interaction that also feeds trace replay (ADR-0006).
- **No accidental cheating:** the air gap guarantees exploits can't reach unintended
  systems and results reflect only the sandboxed target.
- **Operational overhead:** three coordinated stacks plus a hypervisor bridge are more to
  stand up and maintain than a flat single-network deployment, and the enforced isolation
  can complicate debugging of cross-stack connectivity.
