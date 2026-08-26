# ADR-0001: Local-first, zero-budget Ollama model stack

- **Status:** Accepted
- **Date:** 2026-08-25
- **Reference:** `docs/red_team_report.md` §2.1–2.4; `docs/blue_team_report.md` §2.1–2.4

<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

## Context

All inference must run at zero cost on hardware students already own, with a
practical ceiling of roughly 6–8 GB of VRAM per model (GTX 1060 6GB, RTX 2060 6GB,
RTX 3060 8/12GB, Apple M-series shared memory). Two hard constraints drive this.
First, commercial API safety filters from OpenAI, Anthropic, and Google will refuse
to generate exploit payloads, injection strings, or active attack-chain reasoning —
the core work of the Red Team. Second, sending live exploit logs and vulnerability
details to cloud endpoints creates unacceptable data-exfiltration and legal-liability
risk. Models needing 20–40+ GB of VRAM are excluded from the primary architecture.

## Decision

Serve all models locally through **Ollama** using open-weights small language models
that fit within ~4.5 GB VRAM at 4-bit (q4_K_M) quantization. The shared stack is
**Llama 3.1 8B Instruct** for reasoning/planning, **Qwen2.5-Coder-7B-Instruct** for
exploit/patch code generation, and **nomic-embed-text** (137M) for embeddings. On
6–8 GB GPUs only one model is loaded at a time and Ollama swaps models automatically;
12+ GB GPUs may hold two. Both teams share the same model stack. Larger models are an
optional upgrade path only, never a requirement.

## Consequences

- **Enables the work at all:** local, unfiltered models can reason about live
  exploits; no cloud provider would permit this, and the budget stays at zero.
- **No exfiltration surface:** exploit logs and vulnerability data never leave the
  student machine.
- **Latency cost:** model swapping on ≤8 GB GPUs adds ~10–30 s per swap; the pipeline
  must tolerate this.
- **Capability ceiling:** 7–8B local models under token budgets are weaker than
  frontier models, which caps expected ESR/PSR (see ADR-0006 and report §6.4) and
  makes prompt engineering and context assembly the primary levers of quality.
- **Consistency obligation:** the embedding model must stay fixed across all vector
  collections so retrieval remains coherent.
