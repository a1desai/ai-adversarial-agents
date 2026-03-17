# Adversarial Cybersecurity Sandbox
### Dynamic Vulnerability Exploitation & Autonomous Patch Generation

> **CONFIDENTIAL — INTERNAL USE ONLY**  
> Read this entire README before touching any code.

---

## What This Project Is

A localized, air-gapped multi-agent sandbox where:
- **Red Team agents** autonomously discover and exploit vulnerabilities in Dockerized web apps
- **Blue Team agents** detect those exploits, reverse-engineer the attack, and deploy code-level patches

All inference runs **locally** via Ollama. No cloud APIs. No paid services. Zero budget.

---

## Quick-Start (Do This First)

### 1. Prerequisites
- Docker + Docker Compose
- Python 3.11+
- A GPU with 6+ GB VRAM (GTX 1060 / RTX 2060 / RTX 3060 / Apple M-series all work)
- 40 GB free disk space

### 2. Pull the Models (One-Time Setup)
```bash
ollama pull llama3.1:8b-instruct-q4_K_M      # ~4.5 GB — reasoning + log analysis
ollama pull qwen2.5-coder:7b-instruct-q4_K_M  # ~4.5 GB — exploit code + patch generation
ollama pull nomic-embed-text                   # ~300 MB — embeddings
```
> If a teammate already pulled these, you don't need to re-download. Ollama caches locally.

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 4. Spin Up the Stacks
```bash
# Stack 1: Target applications (CVE-Bench containers)
docker-compose -f docker-compose.targets.yml up -d

# Stack 2: Agent infrastructure (Ollama + ChromaDB + LangGraph)
docker-compose -f docker-compose.agents.yml up -d

# Stack 3: Sandbox hypervisor (network bridge + packet logging)
docker-compose -f docker-compose.hypervisor.yml up -d
```

### 5. Smoke Test (Your First Milestone)
```bash
python agents/red_team/recon_agent.py --target http://localhost:8080
```
> Expected output: structured JSON with discovered ports, services, and technologies.  
> If this works, the full stack (Ollama → MCP → LangGraph) is wired correctly.

---

## Repo Structure

```
adversarial-cybersecurity-sandbox/
│
├── README.md                        ← You are here
├── requirements.txt                 ← Python deps
├── docker-compose.yml               ← Top-level orchestrator
├── docker-compose.targets.yml       ← Stack 1: CVE-Bench target apps
├── docker-compose.agents.yml        ← Stack 2: Agent infra
├── docker-compose.hypervisor.yml    ← Stack 3: Network bridge
│
├── /agents/
│   ├── /red_team/                   ← OWNER: Red Team Hires
│   ├── /blue_team/                  ← OWNER: Blue Team Hires
│   └── /shared/                     ← OWNER: Lead — DO NOT MODIFY without approval
│       ├── memory.py                ← ChromaDB collections (all 5)
│       ├── ollama_client.py         ← Ollama wrapper (temperatures locked per role)
│       └── mcp_transport.py         ← MCP layer (output truncation enforced)
│
├── /targets/                        ← OWNER: Infra Hire
├── /hypervisor/                     ← OWNER: Infra Hire
├── /knowledge_base/                 ← OWNER: Knowledge Base Hire
├── /evaluation/                     ← OWNER: Eval Hire
├── /prompts/                        ← OWNER: All hires (version-controlled)
│   ├── /red_team/
│   └── /blue_team/
└── /docs/                           ← Research reports + architecture notes
```

---

## Team Ownership Map

| Folder | Owner | Phase |
|---|---|---|
| `agents/shared/` | **Lead (do not reassign)** | Phase 1 |
| `targets/` + `hypervisor/` | Infra Hire | Phase 1 |
| `knowledge_base/` | Knowledge Base Hire | Phase 1 |
| `agents/red_team/` | Red Team Hire(s) | Phase 2 |
| `agents/blue_team/` | Blue Team Hire(s) | Phase 2 |
| `evaluation/` | Eval Hire | Phase 3 |
| `prompts/` | All hires | Ongoing |

---

## Non-Negotiables (Read Before Writing a Single Line)

These are enforced during code review. Violations = PR rejected.

### 1. AI-Assisted Code Must Be Labeled
```python
# AI-ASSISTED: Generated with [tool]. Reviewed by [your name] on [date].
```
No exceptions. Every AI-generated block, not just files.

### 2. No Cloud AI for Sensitive Logic
Anything touching exploit payloads, CVE data, patch logic, or log analysis goes through **local Ollama only**. No ChatGPT, no Claude API, no Copilot autocomplete for these files.

### 3. Security-Critical Files Need Two Reviewers
These files require sign-off from the lead + one other hire:
- `agents/shared/mcp_transport.py`
- `hypervisor/` (all files)
- Any Docker config with `--cap-drop` or network rules

### 4. PR Template (Required)
Every PR must include:
```
## What this does
## How I tested it
## AI Usage (tool used / what was generated / what you changed)
```

### 5. The Agent is Not the LLM
The LLM is just the cognitive engine. The agent = LLM + prompt layer + guardrails + output validation + token tracking. Never pass raw LLM output directly to the next stage.

---

## Realistic Expectations

| Metric | Frontier Models (GPT-4) | Our Target (7-8B local) |
|---|---|---|
| Red Team Exploit Success Rate | ~13% | **3–5% to start** |
| Blue Team Patch Success Rate | ~23% | **5–10% to start** |

A working pipeline that improves iteratively is the goal. Not matching SOTA on day one.

---

## Key References

- [Red Team Research Report](docs/red_team_report.md)
- [Blue Team Research Report](docs/blue_team_report.md)
- [CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench)
- [LangGraph Docs](https://langchain-ai.github.io/langgraph)
- [Ollama](https://ollama.com)
- [ChromaDB](https://trychroma.com)
- [NVD API](https://nvd.nist.gov/developers)
- [OWASP Secure Coding](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)