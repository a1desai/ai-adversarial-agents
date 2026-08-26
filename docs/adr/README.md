<!-- ============================================================ -->
<!-- OWNER: Aryan Desai (Blue/Eval) -->
<!-- PURPOSE: Architecture Decision Record (ADR) log — index + template. -->
<!-- REFERENCE: docs/red_team_report.md; docs/blue_team_report.md -->
<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->
<!-- ============================================================ -->

# Architecture Decision Records

This directory is the project's **ADR log**. An ADR captures a single significant
architectural decision: the context that forced the choice, the decision itself,
and the consequences we accepted by making it. ADRs are immutable once accepted —
if a later decision reverses an earlier one, we add a new ADR that supersedes it
rather than editing history.

Every ADR here documents a decision that was **already made and justified** in the
two research reports (`docs/red_team_report.md`, `docs/blue_team_report.md`). Each
record links back to the exact report section that is its source of truth. Nothing
in this log is a new decision — this is the durable, skimmable record of choices
that already govern the codebase.

## Log

| # | Title | Status |
| --- | --- | --- |
| [0001](0001-local-first-zero-budget-model-stack.md) | Local-first, zero-budget Ollama model stack | Accepted |
| [0002](0002-chromadb-vector-store.md) | ChromaDB as the local vector store | Accepted |
| [0003](0003-langgraph-supervisor-topology-with-hard-caps.md) | LangGraph supervisor topology with hard caps enforced outside the LLM | Accepted |
| [0004](0004-mcp-transport-truncation-and-patch-allowlist.md) | MCP transport with output truncation and patch-path allowlist | Accepted |
| [0005](0005-reward-computed-outside-the-llm.md) | Reward computed entirely outside the LLM (anti-reward-hacking) | Accepted |
| [0006](0006-deterministic-trace-replay-validity-gate.md) | Deterministic trace replay as the validity gate | Accepted |
| [0007](0007-docker-compose-three-stack-isolation.md) | Docker-compose three-stack network isolation | Accepted |

## Status values

- **Proposed** — under discussion, not yet in force.
- **Accepted** — in force; the codebase reflects this decision.
- **Superseded by ADR-XXXX** — replaced by a later decision; kept for history.
- **Deprecated** — no longer in force and not directly replaced.

## Template

New ADRs copy the block below into `NNNN-short-kebab-title.md`, using the next
free four-digit number. Keep each ADR to a single decision.

```markdown
# ADR-NNNN: <Short Decision Title>

- **Status:** Proposed | Accepted | Superseded by ADR-XXXX | Deprecated
- **Date:** YYYY-MM-DD
- **Reference:** <report file + section this decision comes from>

## Context

<The forces at play: constraints, requirements, and the problem that made a
decision necessary. State facts, not the choice yet.>

## Decision

<The choice we made, stated in one or two clear sentences, plus the key
specifics (which tool, which limits, which topology).>

## Consequences

<What becomes easier and what becomes harder as a result. Include the trade-offs
we knowingly accepted and any follow-on obligations the decision creates.>
```
