<!-- =============================================================================
     docs/audit/red_team_audit.md
     OWNER: Evaluation / KB Hire
     PURPOSE: 20% human-audit record for Red Team AI-assisted code (Issue #67).
              Enumerates the population, states the sample selection, and gives
              a per-file audit row for each sampled file.
     REFERENCE: docs/audit/README.md (framework); README Non-Negotiable #1;
                Red Team Report Section 10.
     ============================================================================= -->
<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

# Red Team — 20% Human Audit Record (Issue #67)

> **STATUS: PENDING HUMAN SIGN-OFF.** The objective fields below (population,
> sample, AI-assist label present, lint status) are completed by the automated
> pre-audit and were verified against the actual file contents on 2026-08-25.
> The branch-coverage gate, the secure-coding review, and the final verdict
> require a human reviewer and are intentionally left blank.

## 1. Population

Per the framework rule, the population is every source file under
`agents/red_team/` plus that team's prompts under `prompts/red_team/`.
(`__pycache__`, `Dockerfile`, and `README.md` are excluded as non-source.)

| # | File | Type | LOC | Security-critical? |
|---|------|------|-----|--------------------|
| 1 | `agents/red_team/exploitation_agent.py` | py | 410 | Yes — payload execution + cognitive core (Report 10.2) |
| 2 | `agents/red_team/supervisor.py` | py | 299 | Partial — guardrail / hard-cap enforcement |
| 3 | `agents/red_team/verification_agent.py` | py | 229 | No |
| 4 | `agents/red_team/recon_agent.py` | py | 225 | No |
| 5 | `agents/red_team/state.py` | py | 63 | No |
| 6 | `prompts/red_team/exploitation_payload_v1.md` | prompt | 75 | Yes — payload template (Report 10.2) |
| 7 | `prompts/red_team/exploitation_agent_v1.md` | prompt | 47 | Partial — exploit prompt |
| 8 | `prompts/red_team/verification_agent_v1.md` | prompt | 38 | No |
| 9 | `prompts/red_team/recon_agent_v1.md` | prompt | 37 | No |

**N = 9.** Sample size = `ceil(0.20 x 9) = ceil(1.8) = 2`.

## 2. Sample selection

Risk-weighted, deterministic (see `docs/audit/README.md` Section 1). The two
highest-risk artifacts are drawn:

1. **`agents/red_team/exploitation_agent.py`** — the pipeline's cognitive core;
   plans and executes attack payloads (`plan_attack`, `execute_payload`). Both
   the largest module (410 LOC) and security-critical under Report 10.2.
2. **`prompts/red_team/exploitation_payload_v1.md`** — the payload template
   itself, explicitly named security-critical logic in Report 10.2. Sampling one
   `.py` and its governing prompt exercises both code and prompt-layer audit.

Both files fall under README Non-Negotiable #2 (local Ollama only for exploit
payloads) and #3-adjacent scrutiny, making them the correct 20% to inspect.

## 3. Audit rows

### 3.1 `agents/red_team/exploitation_agent.py`

| Gate | Field | Result (pre-audit) |
|------|-------|--------------------|
| 1 | AI-assist label present | **No** — header banner has OWNER/PURPOSE/SCOPE/HARD RULES but no `# AI-ASSISTED: ...` attribution line. If this file was AI-drafted, the label must be added before a PASS verdict (README NN #1 / Report 10.3). |
| 2 | Lint status | **Clean** — `ruff check agents/red_team/exploitation_agent.py` → "All checks passed!". |
| 3 | >=80% branch coverage (AI-gen funcs) | _Human to verify_ — targets: `plan_attack`, `execute_payload`, CVE-lookup + memory-retrieval branches. |
| 4 | Secure-coding review | _Human (pen-test experience) to verify_ — confirm payloads never target undiscovered services, no duplicate-payload execution, confidence gating intact. |

Notes: Cognitive core; highest-consequence file in the Red Team pipeline.
Owner is Roshan / Red Team (do not modify during audit — read-only review).

`Human reviewer: __________________   Date: __________   Verdict: [ PASS / FAIL / NEEDS-WORK ]`

### 3.2 `prompts/red_team/exploitation_payload_v1.md`

| Gate | Field | Result (pre-audit) |
|------|-------|--------------------|
| 1 | AI-assist label present | **No** — prompt file contains no `AI-ASSISTED:` attribution note. Add if AI-drafted. |
| 2 | Lint status | **N/A** — Markdown prompt template; ruff (Python linter) does not apply. |
| 3 | >=80% branch coverage | **N/A** — non-executable prompt. |
| 4 | Secure-coding review | _Human to verify_ — confirm the payload template does not encode unscoped/destructive actions and stays within sandbox rules (Report 10.2). |

Notes: Payload template = security-critical logic per Report 10.2; prompt-layer
artifact, so audited for content/scope rather than lint/coverage.

`Human reviewer: __________________   Date: __________   Verdict: [ PASS / FAIL / NEEDS-WORK ]`

## 4. Cycle summary

- Sampled: 2 of 9 (22%, satisfies the >=20% rule).
- AI-assist labels found in sample: **0 of 2** — live finding, applies repo-wide
  to Red Team files (see README pre-audit status).
- Lint: clean where applicable (`.py`); N/A for the prompt.
- **Final human sign-off: PENDING.**
