# Red Team Iteration Round Template

**Issue:** #48 (issues.md)
**Purpose:** Reusable template for each Red Team improvement round.  
Each round: identify top failure category → propose change → run benchmark → record delta.

---

## How to Use This Template

Open one GitHub issue per round titled:
`Red Team Round N — <short description of change>`

Fill in the sections below for each round.

---

## Round Template

### Round N — [Change Description]

**Target failure category (from failure_analysis_red.md):**
- [ ] LLM hallucination / JSON parse failure
- [ ] Supervisor caps not enforced (infinite loop)
- [ ] Missing authentication prerequisite
- [ ] Recon tool unavailability
- [ ] Other: ___

**Hypothesis:**
> One sentence: "Changing X will reduce failure category Y because Z."

**Proposed change:**
| Area | File | Change |
|------|------|--------|
| Prompt | `prompts/red_team/exploitation_agent_vN.md` | Description |
| Agent | `agents/red_team/exploitation_agent.py` | Description |
| Memory | `.chromadb/` via seed script | Description |
| Supervisor | `agents/red_team/supervisor.py` | Description |

**Version bump:** exploitation_agent_v1 → v2 (or relevant file)

**Pre-run checklist:**
- [ ] DVWA running at `http://localhost:8080`
- [ ] DVWA session cookie refreshed at `/tmp/dvwa_cookies.txt`
- [ ] DVWA security level set to `low`
- [ ] Ollama serving llama3.1:8b-instruct-q4_K_M and qwen2.5-coder:7b-instruct-q4_K_M
- [ ] ChromaDB populated (run `python scripts/populate_memory.py` if needed)

**Benchmark command:**
```bash
PYTHONPATH=. .venv/bin/python evaluation/benchmark_runner.py --cve CVE-2019-9053 --red-only
```

**Results:**

| Metric | Baseline | Round N |
|--------|----------|---------|
| ESR | 100% (1 target, clean memory) | |
| Red reward composite | 0.763 | |
| Avg tokens per exploit | ~9,656 | |
| Avg steps per exploit | 4 | |
| Plan parse failures | 8 / 8 (contaminated) | |

**Trace IDs for this round:**
- 

**ESR delta:** +/- ___%

**Qualitative finding:**

**Next round priority:**

---

## Round 1 (Planned) — Fix Supervisor Hard Caps

**Target failure category:** Supervisor caps not enforced (infinite loop)

**Hypothesis:** Moving retry_count increment from `supervisor_route` (conditional edge) to `exploitation_node` (graph node) will ensure state is persisted by LangGraph, preventing the infinite loop.

**Proposed changes:**
| Area | File | Change |
|------|------|--------|
| Supervisor | `agents/red_team/supervisor.py` | Move `retry_count += 1` into `exploitation_node` before returning state |
| Supervisor | `agents/red_team/supervisor.py` | Add `elapsed_seconds` check using `time.time() - engagement_start_time` stored in state |
| State | `agents/red_team/state.py` | Add `engagement_start_time: float` field |

**Expected ESR delta:** No change to ESR on first attempt. Prevents runaway failures, reduces wasted token budget.

---

## Round 2 (Planned) — Truncate Episodic Doc Size

**Target failure category:** LLM hallucination / JSON parse failure

**Hypothesis:** Limiting each episodic memory entry to 150 chars in the prompt (not in storage) will keep attack_planning prompt under 3,000 tokens regardless of episodic collection size, producing reliable JSON responses.

**Proposed changes:**
| Area | File | Change |
|------|------|--------|
| Agent | `agents/red_team/exploitation_agent.py` | In `_plan_with_llm`, truncate each episodic doc: `r["document"][:150]` |

**Expected ESR delta:** +40-60% on subsequent runs (currently 0% with 14+ episodic docs due to context overflow).

---

## Round 3 (Planned) — Add SQLi Playbook to Procedural Memory

**Target failure category:** Recon tool unavailability / correct CVE wrong endpoint

**Hypothesis:** Adding a procedural memory entry with DVWA-specific path `/vulnerabilities/sqli/?id=<payload>&Submit=Submit` and the DVWA cookie requirement will guide the LLM to the correct endpoint even when recon only finds `/login.php`.

**Proposed changes:**
| Area | File | Change |
|------|------|--------|
| Memory | `scripts/seed_red_procedural.py` | Add DVWA SQLi playbook entry referencing DVWA session cookie |

**Expected ESR delta:** +10-20% (reduces endpoint inference failures from recon blindspot).
