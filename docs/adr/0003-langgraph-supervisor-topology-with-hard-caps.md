# ADR-0003: LangGraph supervisor topology with hard caps enforced outside the LLM

- **Status:** Accepted
- **Date:** 2026-08-25
- **Reference:** `docs/red_team_report.md` §4.1–4.3; `docs/blue_team_report.md` §4.1–4.3

<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

## Context

An autonomous multi-agent pipeline on 7–8B models will, left unchecked, saturate its
context window, loop on failed payloads, and burn unbounded tokens. An "agent" in this
system is deliberately more than an LLM: each is a wrapper of prompt layer, hard-coded
guardrails, scoped context assembly, confidence self-assessment, token accounting, and
output validation. The reasoning quality of the small model is fragile, so discipline —
routing, budgets, and stopping conditions — cannot be left to the model's own judgment
or to instructions buried in a prompt.

## Decision

Orchestrate each team as a **LangGraph state machine with a Supervisor node**. Red flow:
`START → Reconnaissance → Supervisor → Exploitation → Supervisor → Verification` (or back
to Exploitation with updated memory). Blue mirrors it across log analysis, root cause,
patch generation, and patch validation nodes. The Supervisor enforces **hard caps in
Python, outside the LLM**: MAX_STEPS = 30, MAX_TOKENS = 50000, and MAX_RETRIES = 3
attempts per target. Conditional edges terminate early on impossible states (e.g. recon
finds no services) and reject invalid proposals (e.g. targeting a service not found in
recon). Guardrails are `if/else` gates that reject non-compliant output *before*
execution — not suggestions in the prompt.

## Consequences

- **Bounded and terminating:** every engagement halts within known step, token, and
  retry limits, so runs are predictable and comparable.
- **Robust to weak models:** malformed or non-compliant LLM output is caught and
  rejected by the wrapper rather than propagating downstream.
- **Engineering shifts to wrappers:** most of the effort is in building disciplined
  agent wrappers and routing logic, not in model selection.
- **Caps constrain reach:** reducing retries from 5 to 3 to conserve tokens can leave
  some solvable targets unresolved — an accepted trade for staying within budget.
- **Enables downstream guarantees:** the per-engagement token ledger and retry tracker
  produced here are the factual inputs the reward function consumes (ADR-0005).
