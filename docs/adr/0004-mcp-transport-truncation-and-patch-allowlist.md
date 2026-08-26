# ADR-0004: MCP transport with output truncation and patch-path allowlist

- **Status:** Accepted
- **Date:** 2026-08-25
- **Reference:** `docs/red_team_report.md` §4.4; `docs/blue_team_report.md` §4.4;
  `prompts/blue_team/root_cause_agent_v1.md` (rule 7);
  `prompts/blue_team/patch_generation_agent_v1.md` (rule 1)

<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

## Context

Tools and containers must be reachable from the LangGraph engine, but their raw output
is far larger than a small model's usable context: a single-host nmap run can exceed
10,000 tokens and log files can exceed 50,000 tokens. Injecting that raw would consume
most of the model's effective window and degrade reasoning. On the Blue side there is a
second hazard — patch application means *writing* into target containers, and an
unconstrained write path lets a patch touch files unrelated to the vulnerability.

## Decision

Use the **Model Context Protocol (MCP)** as the transport layer between isolated Docker
containers and the LangGraph execution engine, with two mandatory behaviors:

1. **Aggressive output truncation.** MCP compresses tool output before it enters the
   context — extracting only open ports, service versions, and detected vulnerabilities
   (target ~1,000 tokens per tool invocation), and time-windowing/endpoint-filtering
   logs for the Blue Team rather than passing raw dumps.
2. **Patch-path allowlist.** Container writes are limited to specific file paths. The
   Root Cause Agent emits a minimal, precise `allowed_patch_paths` whitelist (only files
   it directly inspected), and the Patch Generation Agent must never modify files outside
   that list — enforced as the deployment write whitelist, not merely requested in prose.

## Consequences

- **Context stays usable:** small models see compressed, relevant evidence instead of
  drowning in raw tool output.
- **Blast radius contained:** patch writes cannot stray outside the vetted allowlist,
  reinforcing the minimal-diff rule (see `prompts/README.md`).
- **Truncation risk:** overly aggressive compression could drop a detail an agent needed;
  the extraction rules must be tuned so signal survives.
- **Read/write asymmetry:** Blue gets read access to source and narrowly-scoped write
  access, keeping source inspection and patch deployment cleanly separated.
