# Setup Guide

**Read this before writing any code.**

This is the practical, end-to-end setup walkthrough for new hires. The
project README has the high-level pitch and architecture; this file has
the commands that actually work and the gotchas you'll hit.

---

## 1. What you need before you start

| Requirement | Why |
|---|---|
| **macOS, Linux, or WSL2 on Windows** | Docker + Ollama + Python all work everywhere here. Native Windows is untested. |
| **Python 3.11 or 3.12** | Project pins `>=3.11` in `pyproject.toml`. 3.13 works but isn't the target. |
| **Docker + Docker Compose v2** | Target containers + agent containers all run in Docker. |
| **6+ GB free VRAM** (GTX 1060 / RTX 2060 / Apple M-series) | Ollama models. M1/M2 use unified memory — fine. |
| **40+ GB free disk** | Models (~10 GB) + Docker images (~20 GB) + ChromaDB (~5 GB) + headroom. |
| **`git`** | Obviously. |

Don't have a GPU? You can still run the **unit tests** — they mock Ollama and
ChromaDB. You can't run the full pipeline without Ollama, but you can write
and test code on a CPU-only machine.

---

## 2. First-time setup

### 2.1 Clone the repo

```bash
git clone <repo-url> ai-advarsarial-agents
cd ai-advarsarial-agents
```

### 2.2 Install Ollama and pull models

Install Ollama from <https://ollama.com> (one-line installer per platform).
Then pull the three models we use:

```bash
ollama pull llama3.1:8b-instruct-q4_K_M       # ~4.5 GB — reasoning + log analysis
ollama pull qwen2.5-coder:7b-instruct-q4_K_M  # ~4.5 GB — exploit code + patches
ollama pull nomic-embed-text                   # ~300 MB — embeddings for ChromaDB
```

This is a one-time download (~10 GB total). Ollama caches locally.

Verify Ollama is running:

```bash
ollama list   # should show all three models
curl -s http://localhost:11434/api/tags | head   # API responds
```

If Ollama isn't running: `ollama serve` (or start the desktop app on macOS).

### 2.3 Create a Python virtualenv and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate              # macOS/Linux
# .venv\Scripts\activate               # Windows PowerShell

pip install --upgrade pip
pip install -r requirements.txt
```

If `pip install` fails on `chromadb` or `langgraph`, you probably need
Python 3.11+ — check with `python3 --version`.

### 2.4 Install pre-commit hooks

The project uses `ruff` for linting/formatting, enforced via pre-commit.
Phase 4 has a gate that requires zero ruff warnings — set the hook now so
your commits stay clean automatically.

```bash
pre-commit install
pre-commit run --all-files    # one-time pass to fix existing files
```

### 2.5 Verify the environment

```bash
# Ollama wiring works
python agents/shared/ollama_client.py
# Expected: "✓ Ollama is running and all models are available" + a smoke response

# ChromaDB initializes all 6 collections
python agents/shared/memory.py
# Expected: "ChromaDB initialized successfully" + 6 collection names

# Dummy data loads
python dummy_data/loader.py
# Expected: "loaded 5 dummy CVE records into cve_knowledge"
#           "loaded 5 dummy CVE records into patch_knowledge"
```

If any of these fail, **stop here and fix the environment** before
writing code. They're the load-bearing assumptions everything else makes.

---

## 3. Running tests

### 3.1 The quick version

```bash
source .venv/bin/activate
pytest tests/unit/ -v
```

Expected output (today):

```
80 passed, 2 failed
```

The 2 failing tests are in `tests/unit/test_reward_funtions.py` and assert
that positive reward weights sum to `1.0`. The current implementation sums
to `0.95` (Red) and `0.90` (Blue). This is a known design conflict the
Eval Hire will resolve — it is **not** a regression you introduced.

### 3.2 Test markers — what to run when

| Marker | Requires | When you run it |
|---|---|---|
| `unit` (default) | Nothing — everything mocked | Every commit, before every PR |
| `integration` | ChromaDB + Ollama running | Before merging agent code |
| `smoke` | Full stack (Ollama + Docker + target containers) | After setting up a new machine, or after touching infra |

```bash
pytest                                # unit tests only (default)
pytest tests/unit/ -v                 # unit tests, verbose
pytest tests/smoke/ -m smoke -v       # smoke — needs Ollama + Docker running
pytest tests/integration/ -m integration -v   # not built yet (Phase 3)

# Run one file or one test
pytest tests/unit/test_memory.py -v
pytest tests/unit/test_supervisor.py::TestExploitationRouting -v

# Coverage
pytest tests/unit/ --cov=agents --cov-report=term-missing
```

### 3.3 What each test file covers

| File | What it tests | Why you should care |
|---|---|---|
| `test_memory.py` | All 6 ChromaDB collections initialize, dummy CVE data ingests, retrieval returns relevant results, parallel retrieval uses the right collections per team | If this breaks, no agent can use memory |
| `test_ollama_client.py` | Temperature config is locked, token usage accumulates correctly, model lookup, system prompts prepend to messages | If this breaks, every agent call is suspect |
| `test_mcp_transport.py` | Output truncation enforced, Red Team tool allowlist, **patch-scope whitelist** including traversal/over-strip rejection | **Security critical**. A Blue Team patch must never modify code outside the whitelist. This is the gate. |
| `test_supervisor.py` | Red Team supervisor routing through every phase, hard caps (30 steps / 50K tokens / 3 retries), exploitation success routes to verification, ungrounded claims get rejected | Without this the Red Team would loop forever or miss successes |
| `test_reward_funtions.py` | Reward math is correct, no division-by-zero, perfect/zero runs hit expected bounds | Without this we can't measure improvement across iterations |
| `test_trace_logger.py` | Every action gets a UUID-stamped JSONL entry, traces survive process crashes (immediate flush), summaries finalize | A "successful exploit" with no replayable trace doesn't count. This is the audit trail. |

### 3.4 The smoke test (Phase 1+)

`tests/smoke/test_stack.py` only runs once the full stack is up:

```bash
docker-compose up -d
docker-compose -f docker-compose.targets.yml up -d
ollama serve   # in another terminal if not already running

pytest tests/smoke/ -m smoke -v
```

It verifies: Ollama is reachable, all three models are present, ChromaDB
read/write works, Docker is up, the `sandbox_targets` network exists, DVWA
is running. This is **the** post-setup sanity check. Run it whenever the
stack feels broken.

---

## 4. What this codebase can and can't do today

### Can do
- Import every module cleanly
- Initialize ChromaDB collections
- Load dummy CVE data
- Verify Ollama + token budgeting
- Validate patch scope (with security checks)
- Route the Red Team supervisor
- Log deterministic traces
- Compute reward scores
- Spin up DVWA / WebGoat targets
- Pass 80 unit tests

### Can't do (yet — work for hires)
- Run reconnaissance: `ReconAgent.run()` is a stub
- Plan or execute exploits: `ExploitationAgent` methods are stubs
- Analyze attack logs: `LogAnalysisAgent.analyze()` is a stub
- Generate patches: `PatchGenerationAgent.generate_patch()` is a stub
- Validate patches: `PatchValidationAgent.validate()` is a stub
- Verify successful exploits: `VerificationAgent.verify()` is a stub
- Build the agent containers: no Dockerfiles in `agents/red_team/` or `agents/blue_team/` yet
- Run the hypervisor bridge: only a README in `hypervisor/`
- Execute the benchmark: `evaluation/benchmark_runner.py` doesn't exist yet
- Run the README's quick-start smoke test (`python agents/red_team/recon_agent.py --target ...`) — will raise `NotImplementedError`

**This is intentional.** Phase 0 was about getting the foundation safe. Phase 1
is where these stubs get filled in. See `docs/issues.md` for the full plan.

---

## 5. Daily workflow

```bash
# Start of session
source .venv/bin/activate
git pull origin main
git checkout -b feat/<your-issue-#>-<short-description>

# Work — pre-commit auto-runs ruff on save if you set it up
# ... edit code ...

# Before committing
pytest tests/unit/ -v          # all green (except the known reward-weight 2)
ruff check .                    # zero warnings
ruff format .                   # auto-format

git add <specific files>        # never `git add .` — could include .chromadb/ etc
git commit -m "<conventional commit message>"
```

### Branch naming convention

`feat/<issue-#>-<short>`, `fix/<issue-#>-<short>`, `chore/<issue-#>-<short>`.

Example: `feat/14-recon-agent-implementation`, `fix/1-patch-scope-bugs`.

### Commit messages

Conventional commits, body wrapped at 72 chars:

```
feat(red-team): implement ReconAgent.run() (closes #14)

Add nmap + whatweb scanning via MCP transport. Llama 3.1 8B parses
output into structured JSON matching the schema in recon_agent.py
header.

Files:
  agents/red_team/recon_agent.py
  prompts/red_team/recon_agent_v1.md
  tests/unit/test_recon_agent.py
```

---

## 6. Common gotchas

### "ModuleNotFoundError: No module named 'agents'"
You forgot to activate the venv, or the venv was set up before `pytest.ini`
had `pythonpath = .`. Re-activate, then `pytest tests/unit/`.

### "Ollama not reachable"
Ollama isn't running. Either start the desktop app or `ollama serve` in a
separate terminal. Default port is `11434`.

### Model swapping is slow (10–30s delays)
Expected on 6–8 GB GPUs — Ollama auto-unloads one model to load another.
This is documented as a known cost. On 12+ GB GPUs you can preload both.

### Tests pass locally, fail in CI
Almost always: missing env var, different Python version, or different
Ollama models pulled. Check `.python-version` if it exists, and confirm
your Ollama has the three models from §2.2.

### ChromaDB warns about "legacy embedding function"
A deprecation warning from chromadb >= 0.5. Harmless — fixtures use a fake
embedding function for tests. Real ingestion uses the proper Ollama-backed
embedding function.

### `docker-compose up` fails on `agents/red_team/Dockerfile not found`
The agent Dockerfiles don't exist yet — that's Phase 2 work (issues #16,
#17 in `docs/issues.md`). For now, just `docker-compose -f
docker-compose.targets.yml up -d` to spin up DVWA/WebGoat for development.

---

## 7. What to read next

| If you are | Read |
|---|---|
| Lead | `README.md` → `docs/issues.md` → `docs/red_team_report.md` + `docs/blue_team_report.md` (full) |
| Red Team Hire | `docs/red_team_report.md` (full) → `agents/red_team/README.md` → existing stubs in `agents/red_team/` |
| Blue Team Hire | `docs/blue_team_report.md` (full) → `agents/blue_team/README.md` → existing stubs in `agents/blue_team/` |
| Infra Hire | `targets/README.md` → `hypervisor/README.md` → `docker-compose.*.yml` |
| Knowledge Base Hire | `knowledge_base/README.md` → `agents/shared/memory.py` (collection schemas) |
| Eval Hire | `evaluation/README.md` → `evaluation/reward_red.py` + `reward_blue.py` → `evaluation/trace_logger.py` |
| All hires (rules) | The "Non-Negotiables" section of `README.md` |

The two research reports (`docs/red_team_report.md`, `docs/blue_team_report.md`)
are the source of truth for design decisions. Every weight, every cap,
every retrieval ratio has a justification there.

---

## 8. Where to ask questions

- **GitHub Issues** — primary tracker. Every task has an issue. Comment in-thread.
- **Discord** - AI Council Channel
- **`docs/issues.md`** — full phase-by-phase plan, mapped to GitHub issue numbers.

Don't re-derive answers from scratch when there's a research report covering
the question. The reports are there exactly to prevent that.
