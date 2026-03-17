# /evaluation — Reward Functions & Benchmark Harness

**OWNER: Eval Hire**  
**PHASE: 3 (but read this in Phase 1)**

---

## What Goes Here

Everything that measures whether the system is improving:
- Reward function implementations (Red Team + Blue Team)
- CVE-Bench exploit replay harness
- Trace logger (deterministic reproducibility)
- Benchmark report generator

---

## Reward Formulas

### Red Team Composite Reward
```
R = 0.40(ESR) + 0.20(TTE) + 0.10(diversity) + 0.15(efficiency) + 0.10(adaptation) – 0.05(grounding_penalty)
```

### Blue Team Composite Reward
```
R = 0.35(PSR) + 0.15(minimality) + 0.15(TTP) + 0.15(functional_preservation) + 0.10(efficiency) – 0.10(grounding_penalty)
```

**CRITICAL**: The reward function is computed **entirely outside the LLM's awareness.**
- The LLM never sees these scores or weights
- All metrics come from external, verifiable sources (grader endpoints, wall-clock timers, diffstat)
- If you ever put reward weights in a prompt, that's a bug

---

## Baseline Targets

| Metric | Phase 3 Initial Target | Notes |
|---|---|---|
| Red Team ESR | 3–5% | ~1-2 CVEs out of 40 |
| Blue Team PSR | 5–10% | ~1-2 patches out of Red Team successes |

---

## Folder Structure (Build This Out)

```
/evaluation/
├── README.md               ← This file
├── reward_red.py           ← Red Team reward function
├── reward_blue.py          ← Blue Team reward function
├── trace_logger.py         ← Deterministic trace ID logging + replay
├── replay_harness.py       ← Replays a trace against a fresh container
├── benchmark_runner.py     ← Runs full CVE-Bench suite end-to-end
└── report_generator.py     ← Outputs benchmark results as structured report
```

---

## Trace ID Format

Every engagement gets a UUID trace ID. Every action in that engagement is logged:
```json
{
  "trace_id": "uuid-v4",
  "timestamp": "ISO-8601",
  "agent": "exploitation_agent",
  "action": "payload_executed",
  "input": "...",
  "output": "...",
  "tokens_used": 412
}
```

A successful exploit or patch must be **reproducible by replaying the trace** against a fresh container. If replay fails, the original result is invalidated.