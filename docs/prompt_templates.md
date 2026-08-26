<!-- ============================================================ -->
<!-- OWNER: Aryan Desai (Blue/Eval) -->
<!-- PURPOSE: Single index of every version-controlled prompt template -->
<!--          (red_team + blue_team), populated from each file's header. -->
<!-- REFERENCE: prompts/README.md; docs/red_team_report.md §4.1; -->
<!--            docs/blue_team_report.md §4.1 -->
<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->
<!-- ============================================================ -->

# Prompt Template Index

This page is the single index of every version-controlled prompt template in the
project. Prompts are treated as first-class, reviewed artifacts — not strings
hardcoded in Python — because on 7–8B local models the prompt is the single most
important determinant of agent quality (see `docs/red_team_report.md` §4.1 and
`docs/blue_team_report.md` §4.1).

Every row below is pulled directly from the header block of the corresponding
file under `prompts/`. When a prompt is revised, add a new version file, update
its header, and update the matching row here — do not edit these values by hand
without a corresponding file change.

---

## Red Team Prompts (`prompts/red_team/`)

| File | Agent | Version | Author | Date | Tested on | Result / Delta |
| --- | --- | --- | --- | --- | --- | --- |
| `recon_agent_v1.md` | Recon Agent | v1.0 | Roshan Banisetti | 2026-06-11 | DVWA (http://localhost:8080) | baseline |
| `exploitation_agent_v1.md` | Exploitation Agent — Attack Planning | v1.0 | Roshan Banisetti | 2026-06-30 | DVWA (http://localhost:8080) | baseline |
| `exploitation_payload_v1.md` | Exploitation Agent — Payload Generation | v1.0 | Roshan Banisetti | 2026-07-17 | DVWA (http://localhost:8080) | baseline |
| `verification_agent_v1.md` | Verification Agent — Exploit Confirmation | v1.0 | Roshan Banisetti | 2026-07-17 | DVWA (http://localhost:8080) | baseline |

## Blue Team Prompts (`prompts/blue_team/`)

| File | Agent | Version | Author | Date | Tested on | Result / Delta |
| --- | --- | --- | --- | --- | --- | --- |
| `log_analysis_agent_v1.md` | Log Analysis Agent — Attack Chain Reconstruction | v1.0 | Aryan Desai | 2026-07-25 | DVWA (http://localhost:8080) | baseline |
| `root_cause_agent_v1.md` | Root Cause Agent — Vulnerability Analysis | v1.0 | Aryan Desai | 2026-07-25 | DVWA (http://localhost:8080) | baseline |
| `patch_generation_agent_v1.md` | Patch Generation Agent — Minimal Fix Synthesis | v1.0 | Aryan Desai | 2026-07-25 | DVWA (http://localhost:8080) | baseline |
| `patch_validation_agent_v1.md` | Patch Validation Agent — Dual Validation Rubric | v1.0 | Aryan Desai | 2026-07-25 | DVWA (http://localhost:8080) | baseline |

> All eight templates are currently at v1.0 with `Change: Initial version`, so the
> `Result / Delta` column reads **baseline** for every file — there is no prior
> version to measure an ESR/PSR delta against yet. Once a v2 lands, its row records
> the ESR (Red) or PSR (Blue) delta relative to its predecessor.

---

## Mandatory Content Rules (from `prompts/README.md`)

Two rules are non-negotiable and must appear in every prompt of the respective
team. They are enforced by review, not just convention:

1. **Red Team — always reference retrieved CVE data.** Every Red Team prompt must
   instruct the agent to reference the retrieved CVE data (CVE ID, technique,
   knowledge-base context) *before* proposing or generating an attack vector. This
   grounds exploitation in real vulnerability data rather than model speculation.
   (See `recon_agent_v1.md`, `exploitation_agent_v1.md`, `exploitation_payload_v1.md`
   rule 1, and `verification_agent_v1.md` rule 1.)

2. **Blue Team — always produce minimal diffs.** Every Blue Team prompt must
   instruct the agent to produce the smallest possible change that fixes the
   vulnerability — never rewrite functions unnecessarily, never reformat unrelated
   code, never touch files outside `allowed_patch_paths`. (See
   `patch_generation_agent_v1.md` rule 1 and the `allowed_patch_paths` whitelist
   emitted by `root_cause_agent_v1.md` rule 7.)

---

## Header Contract

Every prompt file **must** open with this header block (from
`prompts/README.md`). All eight current files satisfy it:

```
# Prompt: [Agent Name]
# Version: vX.X
# Author: [name]
# Date: [date]
# Change: [what changed from previous version and why]
# Tested on: [which CVEs / targets]
# Result: [ESR/PSR delta from previous version]
```

---

## Versioning Workflow

The prompt library follows a strict, append-only versioning discipline
(`prompts/README.md`, "Rules for Prompt Files"):

1. **One file per agent per version.** A revised prompt is a *new* file with an
   incremented suffix — `exploitation_agent_v1.md` → `exploitation_agent_v2.md` —
   never an in-place overwrite of an existing version.
2. **Never delete old versions.** A superseded prompt is renamed with a
   `_deprecated` suffix, never removed, so A/B history stays reproducible.
3. **Every prompt change is a PR.** No exceptions — prompt edits go through the
   same review gate as code, and the author owns their team's subfolder.
4. **Update this index in the same PR.** When a new version lands, add its row
   here with the ESR/PSR delta from the header's `Result` line so this page stays
   the accurate, single source of truth.
