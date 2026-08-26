<!-- =============================================================================
     docs/audit/README.md
     OWNER: Evaluation / KB Hire
     PURPOSE: Governance framework for the 20% human audit of AI-assisted code.
              Defines the sampling rule, the audit checklist, and how a human
              reviewer records sign-off.
     REFERENCE: README Non-Negotiable #1; Red/Blue Team Report Section 10
                (AI-Assisted Development Governance) and Section 7 / 9
                (20% human audit sampling of successful exploits).
     ============================================================================= -->
<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

# 20% Human Audit — Governance Framework

This directory holds the **audit record** required by README Non-Negotiable #1
and Report Section 10 (AI-Assisted Development Governance). It exists so that a
human reviewer can confirm, on the record, that AI-assisted code in this repo
meets the project's quality and attribution gates.

The audit has two layers:

1. **Automated pre-audit** (this deliverable) — a machine-checkable pass that
   populates every objective field: which files exist, whether each carries the
   required AI-assist label, and whether each passes the linter. This is
   completed here and kept current.
2. **Human sign-off** (pending) — a person with the relevant expertise reviews
   the sampled files against the checklist below and signs the sign-off line.
   **The automated pre-audit does not replace the human review — it prepares
   it.** Every sign-off line in this directory is intentionally left blank until
   a human completes it.

---

## 1. The 20% sampling rule

The governance model does **not** require a full manual review of every
AI-assisted artifact — that does not scale. Instead it mandates a **random /
risk-weighted 20% sample** so that audit effort is bounded while every file
still has a standing probability of being reviewed. This mirrors Report
Section 9/7, which prescribes a "random 20% sample of successful exploits [that]
undergoes human review by a team member with penetration-testing experience."

We apply the same 20% principle to the **codebase audit** of each team:

- **Population (per team):** all source files under `agents/<team>/` plus that
  team's prompt files under `prompts/<team>/`.
- **Sample size:** `ceil(0.20 x N)` where `N` is the population count. `ceil`
  (not `round`) guarantees at least one file is always sampled, even for small
  populations.
- **Selection rule — risk-weighted, deterministic:** files are ranked
  highest-risk-first and the top `ceil(0.20 x N)` are drawn. Risk ranking:
  1. Files carrying a **SECURITY-CRITICAL** designation in their header banner
     (e.g. patch-generation / patch-validation logic, payload execution).
  2. **Cognitive-core** modules (the agent that plans/executes the primary
     action of the pipeline).
  3. Ties broken by source lines of code (LOC), descending.

  A risk-weighted rule is used instead of a blind random draw because the
  highest-consequence files (patch logic, payload execution) are the ones the
  auditor most needs to see; the rule is stated explicitly per team so the
  selection is reproducible and reviewable. A future cycle may rotate the
  sample (e.g. exclude previously-audited files) to widen coverage over time.

---

## 2. What an audit checks

For every sampled file the human reviewer confirms all four gates. These are
drawn directly from README Non-Negotiable #1 and Report Section 10.4
(Quality Gates for AI-Generated Code):

| # | Gate | Pass criterion | Source |
|---|------|----------------|--------|
| 1 | **AI-assist labeling present** | The file (or each AI-generated block) carries the attribution comment `# AI-ASSISTED: Generated/modified with [tool]. Reviewed by [name] on [date].` | README NN #1; Report 10.3 |
| 2 | **Linter clean** | `ruff check` passes with **zero** warnings; `ruff format` reports no diff. | Report 10.4 |
| 3 | **>=80% branch coverage for AI-generated functions** | Functions substantially AI-drafted have unit tests reaching at least 80% branch coverage. | Report 10.4 |
| 4 | **Secure-coding review (patch logic)** | For Blue Team patch-generation / patch-validation code (and Red Team payload-execution code), a human with security knowledge confirms the logic does not disable security controls, stays within its allowed scope, and introduces no new vulnerability. | README NN #2/#3; Report 10.2 |

Notes on scope:
- Gates 1 and 2 are **objective** and are pre-filled by the automated pre-audit
  in each team's audit file.
- Gates 3 and 4 require **human judgment** and are left for the reviewer. The
  pre-audit records the relevant context (e.g. whether a file is
  security-critical) but does not assert a pass.

---

## 3. How to record sign-off

Each sampled file in `red_team_audit.md` / `blue_team_audit.md` ends with a
sign-off line. To complete the audit for a file, the reviewer fills it in
verbatim:

```
Human reviewer: __________________   Date: __________   Verdict: [ PASS / FAIL / NEEDS-WORK ]
```

- **PASS** — all four gates satisfied.
- **NEEDS-WORK** — a gate is unmet but remediable (e.g. missing label, coverage
  gap); record the follow-up item in the file's Notes column.
- **FAIL** — a security-relevant defect found; must be root-caused and
  documented before the file can be re-audited.

An audit cycle is **complete** only when every sampled file for both teams has a
signed verdict. Until then this record is explicitly **PENDING HUMAN SIGN-OFF**.

---

## 4. Files in this directory

| File | Contents |
|------|----------|
| `README.md` | This framework: sampling rule, checklist, sign-off procedure. |
| `red_team_audit.md` | Red Team population, 20% sample, and per-file audit rows. |
| `blue_team_audit.md` | Blue Team population, 20% sample, and per-file audit rows. |

---

## 5. Current status (automated pre-audit)

- **Population enumerated:** yes, both teams.
- **Sample selected:** yes, per the risk-weighted rule above.
- **AI-assist labels:** verified against actual file contents. As of this
  pre-audit, **no** source file under `agents/red_team/`, `agents/blue_team/`,
  `prompts/red_team/`, or `prompts/blue_team/` carries the required
  `AI-ASSISTED:` attribution comment. This is a live finding — see each team's
  audit file. If any of these files were AI-drafted, the label must be added
  before a human verdict of PASS can be recorded.
- **Linter:** `ruff check` passes clean on all sampled `.py` files.
- **Human sign-off:** **PENDING** for every sampled file.
