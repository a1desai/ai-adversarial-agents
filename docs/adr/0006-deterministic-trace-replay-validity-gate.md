# ADR-0006: Deterministic trace replay as the validity gate

- **Status:** Accepted
- **Date:** 2026-08-25
- **Reference:** `docs/red_team_report.md` §6.1–6.3; `docs/blue_team_report.md` §6.1–6.3

<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

## Context

Autonomous agents produce success claims, but a claim is not proof. A model can
hallucinate an exploit, or a "success" can be a flaky one-off that depends on residual
container state. The primary validation instrument is CVE-Bench (40 critical-severity
CVEs with containerized targets and automated graders), and results must hold up to
human audit and to the reward function that consumes them (ADR-0005). We therefore need
an objective, repeatable gate that separates real successes from artifacts.

## Decision

Make **deterministic trace replay the validity gate.** Every engagement gets a unique
trace ID, and every action — tool invocation, LLM prompt/response, and state
transition — is logged with timestamps. A claimed success (Red exploit or Blue patch) is
only considered valid if replaying the logged actions against a **fresh, clean instance**
of the target container reproduces the outcome. **If a replay fails, the original success
is invalidated.** Replay sits inside a multi-stage protocol: automated grading, trace
replay, independent Verification-Agent confirmation, and a random 20% human audit of
confirmed successes. For the Blue Team, replaying the Red Team's original exploit against
the patched container is exactly what confirms neutralization.

## Consequences

- **Only reproducible results count:** hallucinated or state-dependent "successes" are
  filtered out before they reach metrics or reports.
- **Clean, honest numbers:** ESR/PSR reflect exploits/patches that genuinely work on a
  fresh target, which is what makes the reward function (ADR-0005) trustworthy.
- **Determinism is an obligation:** logging must be complete and faithful, and targets
  must reset to a clean state for replay — flaky or missing logs break the gate.
- **Extra compute per success:** each confirmed success costs at least one additional
  full replay run, which the pipeline must budget for.
