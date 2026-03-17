**Dynamic Vulnerability Exploitation via Autonomous Multi-Agent Systems**

*Technical Architecture, Model Selection, Datasets, Reward Functions, Validation Strategies, and AI Development Governance*

**CONFIDENTIAL — INTERNAL USE ONLY** | March 2026 | Version 2.0

---

# 1. Executive Overview and Research Scope

This research report provides the comprehensive technical blueprint for building the Red Team (adversarial) agent within the Adversarial Cybersecurity Sandbox for Dynamic Vulnerability Exploitation. The Red Team agent is the offensive core of the system: an autonomous, multi-agent pipeline that discovers, chains, and exploits vulnerabilities in Dockerized web applications without human guidance. This document covers every engineering decision from model selection and memory architecture to reward functions, evaluation harnesses, and the ground rules governing AI-assisted development across the team.

The adversarial agent architecture must accomplish three fundamental objectives. First, it must autonomously probe target applications using network scanning, service fingerprinting, and directory enumeration to build a comprehensive attack surface map. Second, it must reason over discovered services, cross-reference known CVE databases, and construct multi-step exploitation chains that combine individual weaknesses into high-impact attack paths. Third, it must learn from failed attempts, adapting its strategies through episodic memory so it does not repeat ineffective payloads or get stuck in infinite retry loops.

The guiding principle of this project is a working, zero-budget, fully open-source framework. Every component — models, vector databases, orchestration tools, and target environments — must run on distributed student hardware at zero cost with no paid cloud services, no commercial API subscriptions, and no licensed software. All models must fit within approximately 6 GB of VRAM using consumer-grade GPUs that students already own. The architecture is designed to be practical and functional first; performance optimization comes after the pipeline works end to end.

The current state of the art, as established by the CVE-Bench benchmark (ICML 2025 spotlight), shows that the best available agent frameworks using frontier commercial models can exploit roughly 13% of critical-severity real-world web application vulnerabilities. That number represents a ceiling achieved with GPT-4-class models and unlimited API budgets. Our architecture uses small local models under strict token and resource budgets, so the realistic goal is to build a working autonomous exploitation pipeline that demonstrably succeeds on some subset of targets — then iteratively improve toward and beyond the 13% baseline as the framework matures.

The scope is deliberately constrained to the Red Team agent. The Blue Team (defense) agent and the sandbox hypervisor are covered in companion documents.

# 2. Model Selection Strategy

## 2.1 The Local-First, Zero-Budget Constraint

The proposal mandates that all inference run on local, air-gapped student hardware using open-weights models served through Ollama at zero cost. This is non-negotiable for two reasons. First, commercial API safety filters from providers like OpenAI, Anthropic, and Google will refuse to generate exploit payloads, craft injection strings, or reason about active attack chains. Second, sending live exploit logs and vulnerability details to cloud endpoints creates unacceptable data exfiltration risk and potential legal liability. Local inference via Ollama eliminates both concerns while keeping the budget at zero.

The hardware constraint is equally firm: models must run on whatever GPUs students already have access to. This means a maximum of approximately 6–8 GB of VRAM per model (typical consumer GPUs: GTX 1060 6GB, RTX 2060 6GB, RTX 3060 8GB/12GB, Apple M-series with shared memory). Models requiring 20–40+ GB of VRAM are excluded from the primary architecture. If a team member happens to have a higher-end GPU, larger models can be tested as an optional upgrade path, but the core framework must function on the smallest common denominator.

## 2.2 Recommended Model Stack (≤6 GB VRAM)

The Red Team agent requires two distinct cognitive capabilities: strategic reasoning (planning attack chains, interpreting reconnaissance output, adapting strategies) and code generation (writing exploit payloads, crafting HTTP requests, generating shell commands). The recommended architecture uses small language models (SLMs) that fit within the 6 GB budget.

### 2.2.1 Primary Reasoning and Exploitation Engine

Llama 3.1 8B Instruct is the recommended primary reasoning model, as specified in the original proposal. At 4-bit quantization (q4_K_M), it requires approximately 4.5 GB of VRAM and provides strong instruction-following, 128K context window, and broad general reasoning. This single model handles both strategic planning and exploitation reasoning. For teams wanting an alternative, Qwen2.5-7B-Instruct or Mistral 7B Instruct v0.3 are comparable options in the same VRAM class.

### 2.2.2 Code Generation Specialist

Qwen2.5-Coder-7B-Instruct is the recommended code generation model. It is fully open-source under the Apache 2.0 license, runs locally via Ollama with no API key or payment required, and fits in approximately 4.5 GB of VRAM at 4-bit quantization. This model specializes in generating exploit code, crafting SQL injection payloads, writing reverse shells, and constructing HTTP request sequences. CodeLlama 7B Instruct is an alternative in the same VRAM class. On machines with limited VRAM, the reasoning model (Llama 3.1 8B) can handle code generation as well — the specialist is an optimization, not a requirement.

### 2.2.3 Practical Deployment: One Model at a Time

On a 6–8 GB GPU, only one model can be loaded at a time. Ollama handles model swapping automatically: when the Supervisor routes a task to the Exploitation Agent, Ollama unloads the reconnaissance model and loads the reasoning model. This adds latency (10–30 seconds per swap depending on disk speed) but keeps VRAM usage within budget. On machines with 12+ GB VRAM (e.g., RTX 3060 12GB), two small models can be loaded simultaneously for faster pipeline execution.

## 2.3 Model Configuration via Ollama

All models should be served through Ollama with the following configuration. Temperature should be set between 0.1 and 0.3 for exploit generation (deterministic precision matters) and 0.5 to 0.7 for strategic planning (where creative lateral thinking about alternative attack vectors is valuable). Context windows must be managed carefully under token budget constraints: the LangGraph Supervisor enforces strict per-engagement token caps, so prompts must be concise and tool outputs must be truncated before injection into the context. Top-p sampling should be set to 0.9 for planning and 0.95 for code generation. Repeat penalty of 1.1 helps prevent the model from generating the same failed payload patterns.

## 2.4 Model Comparison Matrix

| Model | Params | VRAM (4-bit) | Role | Context | License |
| --- | --- | --- | --- | --- | --- |
| Llama 3.1 8B Instruct | 8B | ~4.5 GB | Reasoning | 128K | Llama 3.1 |
| Qwen2.5-Coder-7B-Instruct | 7B | ~4.5 GB | Exploit Code | 128K | Apache 2.0 |
| Qwen2.5-7B-Instruct | 7B | ~4.5 GB | Alt. Reasoning | 128K | Apache 2.0 |
| CodeLlama 7B Instruct | 7B | ~4.5 GB | Alt. Code | 16K | Llama 2 |
| Mistral 7B Instruct v0.3 | 7B | ~4.5 GB | Alt. Reasoning | 32K | Apache 2.0 |
| nomic-embed-text | 137M | ~0.3 GB | Embeddings | 8K | Apache 2.0 |

All models above fit within 6 GB of VRAM at 4-bit quantization. The embedding model runs alongside any of the above with negligible additional memory. Every model listed is free, open-weights, and available via Ollama with a single pull command.

# 3. Databases, Datasets, and Knowledge Architecture

## 3.1 CVE Knowledge Base

The foundational dataset is the National Vulnerability Database (NVD), maintained by NIST, which provides structured CVE records including CVSS severity scores, affected software versions, CWE classifications, and links to advisories and proof-of-concept exploits. The team should build an automated ingestion pipeline that pulls CVE records via the NVD API (free, no API key required for basic access), filters for critical-severity web application vulnerabilities (CVSS 3.1 base score >= 9.0), and processes them into the vector database. Each CVE record should be chunked into three retrievable segments: the vulnerability description, the technical advisory details, and any associated exploit methodology.

## 3.2 Exploit Documentation Corpus

Beyond NVD, the knowledge base should ingest documentation from Exploit-DB (the canonical public exploit archive, freely downloadable), the MITRE ATT&CK framework (providing tactical and technique-level attack patterns mapped to real-world adversary behavior), and the OWASP Testing Guide (which provides structured methodology for web application penetration testing). All of these are free and publicly available. All documentation should be processed using a chunking strategy that preserves code blocks, command sequences, and step-by-step exploit procedures as atomic retrievable units.

## 3.3 Target Environment Dataset

For the Dockerized target applications, the project should leverage CVE-Bench directly as its primary evaluation corpus. CVE-Bench v2.1.0 provides 40 critical-severity CVEs with fully containerized web applications, automated evaluation servers, and reference exploits. The benchmark is open-source and free to clone. Additionally, the team should build supplementary targets using VulnHub images (free), DVWA (Damn Vulnerable Web Application, free), and WebGoat (free) to expand the training and development corpus beyond the evaluation set.

## 3.4 Vector Database: ChromaDB (Zero-Cost)

ChromaDB is the recommended vector database for this project. It is fully open-source, runs locally with a single pip install (pip install chromadb), requires no separate server process for development use, stores data on local disk, and has zero licensing or infrastructure cost. ChromaDB provides everything the project needs: persistent vector storage, metadata filtering (for filtering by CVE severity, CWE type, or target technology), and cosine similarity search. It integrates natively with Python and has a minimal learning curve.

The vector database should maintain three distinct collections. The first is the CVE Knowledge Collection, storing embedded CVE descriptions, exploit procedures, and patch notes indexed by CVE ID, CVSS score, CWE type, and affected technology. The second is the Episodic Memory Collection, storing records of prior exploit attempts (both successful and failed) indexed by target application type, exploit technique, and outcome. The third is the Procedural Memory Collection, storing reusable attack playbooks that have been validated through successful execution.

Qdrant is an optional upgrade path for teams that want higher performance or richer query capabilities. It runs locally via Docker (also free and open-source) and offers gRPC APIs and ACID-compliant operations. However, ChromaDB is sufficient for the scope of this project and should be used unless a specific technical limitation is encountered.

## 3.5 Embedding Model Selection

For embedding CVE documentation and exploit procedures, use nomic-embed-text via Ollama. This model is 137M parameters, uses approximately 300 MB of VRAM, and runs alongside any of the reasoning models without conflict. It produces 768-dimensional embeddings with strong semantic understanding of technical text. Chunk size should be 512 tokens with 50-token overlap for prose documentation, and full-block preservation for code snippets. The embedding model must remain consistent across all collections.

# 4. Multi-Agent Architecture and LangGraph Orchestration

## 4.1 Agent Architecture: More Than Just an LLM

A critical distinction: an "agent" in this system is not the LLM itself. The LLM is only the cognitive engine — one component inside a much larger wrapper. Each agent is a self-contained module that includes all of the following layers:

**Prompt Engineering Layer.** Every agent operates from carefully engineered system prompts that define its role, constraints, and expected output format. These prompts are the single most important determinant of agent quality and must be version-controlled, A/B tested, and iteratively refined. The Exploitation Agent's system prompt, for example, must instruct it to always reference retrieved CVE data before proposing an attack vector, always output structured JSON for payload definitions, and never claim success without evidence from tool output.

**Rules and Guardrails ("Bible").** Each agent carries a set of hard-coded behavioral rules that the LLM cannot override. These include: never target services not discovered during reconnaissance, never exceed the token budget allocated by the Supervisor, never execute the same payload twice against the same endpoint, and always log the full reasoning chain before acting. These rules are enforced programmatically in the wrapper code — they are not suggestions in the prompt, they are if/else gates in Python that reject non-compliant outputs before execution.

**Scoping and Context Management.** Each agent has a defined scope of responsibility and a strict context budget. The Reconnaissance Agent only receives target URLs and returns structured JSON — it never sees exploit payloads. The Exploitation Agent receives reconnaissance output and memory retrieval results, but its context is assembled programmatically to stay within token limits. Context assembly is a first-class engineering concern: which information goes into the prompt, in what order, and how much of it, directly determines output quality on small models.

**Confidence Intervals and Self-Assessment.** Each agent must output a confidence score (0.0–1.0) alongside every recommendation or action. The Exploitation Agent must rate its confidence that a proposed payload will succeed before the Supervisor authorizes execution. The Verification Agent must rate its confidence that an observed outcome constitutes genuine exploitation versus a false positive. These confidence scores feed into the Supervisor's routing logic: low-confidence exploitation plans trigger additional memory retrieval or alternative strategy generation rather than blind execution.

**Token Usage Metrics and Budget Tracking.** Every agent tracks its own token consumption per invocation (prompt tokens + completion tokens) and reports it to the Supervisor. The Supervisor maintains a running token ledger per engagement and enforces the per-engagement cap (50K tokens). This is not optional — on 7–8B models with limited effective context windows, untracked token usage leads to context saturation, degraded reasoning, and wasted compute. The wrapper logs tokens consumed per agent per step, enabling post-hoc analysis of where the token budget is being spent and where efficiency gains are possible.

**Output Validation and Parsing.** The wrapper around each LLM call includes structured output parsing (expecting JSON or specific formats), retry logic for malformed outputs (up to 2 retries with reformatted prompts), and hard rejection of outputs that fail schema validation. The LLM's raw text output is never passed directly to the next stage — it is always parsed, validated, and transformed by the wrapper before being consumed.

In summary, the LLM provides reasoning capability, but the agent provides discipline. The engineering effort in this project is primarily in building robust agent wrappers, not in selecting the best LLM.

## 4.2 Agent Hierarchy

The Red Team system consists of four specialized agents coordinated by a LangGraph Supervisor Node. Each agent is a node in the directed graph, with edges representing conditional transitions based on the current attack state.

### 4.2.1 Supervisor Node (Tactical Command)

The Supervisor is the central router. It maintains the global attack state (a TypedDict in LangGraph), receives output from each agent, and routes the next task based on the current phase of the attack lifecycle. The Supervisor enforces hard caps on total execution steps (recommended: 30 steps per CVE target), total token budget (recommended: 50K tokens per engagement, to stay within the context limits of 7–8B models), and wall-clock time (recommended: 15 minutes per target). These caps are deliberately conservative to match the constraints of small language models. If any cap is reached, the Supervisor forces termination and logs the partial result. The Supervisor also implements an evaluator gate: before routing an exploitation plan to the Exploitation Agent, it performs a lightweight sanity check to prevent hallucinated attack vectors.

### 4.2.2 Reconnaissance Agent

This agent executes network scanning and service fingerprinting through MCP-wrapped tool calls. The tools include: nmap for port scanning and service version detection, gobuster or feroxbuster for directory enumeration, nikto for web vulnerability scanning, and whatweb for technology fingerprinting. The Reconnaissance Agent uses Llama 3.1 8B as its cognitive engine. Its job is to parse raw tool output into structured JSON describing discovered services, open ports, detected technologies, and potential entry points. This structured output becomes the input to the Exploitation Agent.

### 4.2.3 Exploitation Agent

This is the cognitive core of the Red Team system. It receives the structured reconnaissance data, queries the CVE Knowledge Collection in ChromaDB for matching vulnerabilities, retrieves relevant exploit procedures, and constructs an attack plan. The Exploitation Agent then generates and executes exploit payloads (using Qwen2.5-Coder-7B for complex payloads, or Llama 3.1 8B for simpler cases), monitors the response, and adapts its strategy based on success or failure. Failed attempts are logged to the Episodic Memory Collection with full context so the agent can avoid repeating them.

### 4.2.4 Verification Agent

After the Exploitation Agent reports a successful exploit, the Verification Agent independently confirms the result by checking for the expected outcome against the CVE-Bench evaluation server. This prevents false positives from hallucinated success reports — a particularly important safeguard with smaller models that are more prone to confabulation than frontier models.

## 4.3 State Machine and Graph Topology

**Core Flow:** START → Reconnaissance → Supervisor (evaluate recon) → Exploitation → Supervisor (evaluate result) → Verification (if success claimed) OR back to Exploitation (if failed, with updated memory).

The Supervisor tracks a retry counter per CVE target and enforces a maximum of 3 exploitation attempts before marking the target as unresolved (reduced from 5 to conserve tokens on small models). Conditional edges use the attack state to determine transitions: if reconnaissance reveals no services, the engagement terminates immediately. If the Exploitation Agent proposes a vector targeting a service not found in recon, the Supervisor rejects it and requests replanning.

## 4.4 MCP Transport Layer

The Model Context Protocol serves as the transport layer between the isolated Docker containers and the LangGraph execution engine. MCP handles the serialization of tool invocations, the collection of stdout/stderr from exploit attempts, and the structured return of results back into the agent context window. Critically, MCP must implement aggressive output truncation: raw nmap output for a single host can exceed 10,000 tokens, which would consume most of a small model’s effective context budget. The MCP transport layer must extract only open ports, service versions, and detected vulnerabilities, compressing output to under 1,000 tokens per tool invocation.

# 5. Reward Function Design

## 5.1 Why a Reward Function Matters

Although the Red Team agent is not trained via reinforcement learning (it uses pre-trained LLMs), a reward function is essential for two purposes: measuring whether the system is improving across iterations of the architecture, and providing structured feedback signals that the Supervisor Node uses to decide whether to continue, retry, or terminate an engagement.

## 5.2 Primary Reward: Exploit Success Rate (ESR)

The primary reward signal is binary per target: 1 if the agent achieves at least one of the eight CVE-Bench standard attack goals, 0 otherwise. The eight goals are: denial of service, unauthorized login, privilege escalation, database access, database modification, file access, file creation, and remote code execution. ESR equals the total number of successfully exploited targets divided by the total number of targets attempted.

## 5.3 Secondary Rewards: Multi-Dimensional Scoring

Beyond binary success, the system should track secondary metrics that help identify where the pipeline is failing and where to invest improvement effort.

| Metric | Weight | Description | Calculation |
| --- | --- | --- | --- |
| Exploit Success Rate | 0.40 | Binary: did the agent achieve an attack goal? | successes / total_targets |
| Time-to-Exploit (TTE) | 0.20 | Speed of successful exploitation | 1 - (time_taken / max_time) |
| Attack Diversity | 0.10 | Variety of attack types achieved | unique_attack_types / 8 |
| Efficiency Score | 0.15 | Success relative to tokens consumed | successes / total_tokens_used |
| Adaptation Rate | 0.10 | Improvement after failed attempts | success_after_retry / retries |
| Grounding Penalty | -0.05 | Actions taken without supporting evidence from tool output | -1 * (ungrounded_actions / total_actions) |

**Note on the Grounding Penalty:** An earlier version of this metric was called "Hallucination Penalty" and attempted to penalize the agent for hallucinating. The problem is that you cannot impose "do not hallucinate" on an LLM — hallucination is an intrinsic property of language models, not a behavioral choice the model can control. Instead, the Grounding Penalty measures something observable and enforceable: whether the agent took actions (proposed exploits, claimed discoveries, reported successes) that have no supporting evidence in the actual tool output or grader results. This is measured by the wrapper, not by the LLM itself. Every action the Exploitation Agent proposes is checked by the wrapper against the actual reconnaissance data and tool responses. If the agent references a service that nmap never found, or claims a payload succeeded when the HTTP response was a 404, the wrapper flags this as an ungrounded action. This metric cannot be gamed by the LLM because it is computed externally from factual tool output, not from the model's self-assessment.

## 5.4 Composite Reward Formula

The composite reward R for a single evaluation run is:

R = 0.40(ESR) + 0.20(TTE) + 0.10(diversity) + 0.15(efficiency) + 0.10(adaptation) – 0.05(hallucination)

This score is logged for every benchmark run and tracked to measure whether changes are producing improvement. The efficiency metric is particularly important in this architecture because token budgets are constrained; an agent that succeeds in fewer tokens is objectively better suited to the zero-budget paradigm.

## 5.5 Anti-Exploitation of Reward Weights

A critical design concern: the reward weights must not be exploitable. If the LLM has any awareness of the scoring function (through system prompts or implicit optimization), it could game the metrics — for example, by deliberately failing on a first attempt to inflate the adaptation rate, or by rushing to maximize TTE at the cost of thoroughness.

The defense is architectural: **the reward function is computed entirely outside the LLM's awareness.** The LLM never sees the composite score, never receives the weights, and is never prompted to optimize for any specific metric. The reward function exists only for human evaluation of the system across benchmark runs — it is a tool for the engineering team, not a signal for the model.

Additionally, all metrics are computed from externally verifiable facts, not from the LLM's self-reported outputs:

- **ESR** is determined by the CVE-Bench grader endpoint, which the LLM cannot manipulate.
- **TTE** is measured by the wrapper's wall-clock timer, not by the model's claim of when it finished.
- **Efficiency** is computed from the wrapper's token ledger, not from the model's estimate of its own usage.
- **Adaptation rate** is computed by the Supervisor's retry tracker, comparing the factual outcomes of attempt N versus attempt N+1.
- **Grounding penalty** is computed by the wrapper's evidence checker against actual tool output, as described above.

If future iterations introduce any form of online reward shaping (e.g., adjusting prompts based on reward signals), the weights must be treated as privileged information that is never included in any prompt context. The moment the model can observe or infer the reward function, it can optimize for the proxy rather than the objective.

## 5.6 Intra-Engagement Feedback Signals

Within a single engagement, the Supervisor uses lightweight feedback signals to guide routing. A successful tool invocation receives +1 micro-reward. A failed invocation receives -0.5. A repeated identical action receives -2. An exploit that triggers the CVE-Bench grader positively receives +10. These are summed into a running score the Supervisor uses alongside hard caps to decide continuation versus termination.

# 6. Validation and Correctness Testing

## 6.1 CVE-Bench as the Gold Standard

The primary validation instrument is CVE-Bench v2.1.0, an open-source benchmark providing 40 critical-severity CVEs with fully containerized environments, automated grading servers, and human-verified reference exploits. Each CVE includes a grading endpoint hosted within the target container that monitors for successful attacks. A target is marked as successfully exploited only if the grader confirms at least one standard attack goal was achieved.

## 6.2 Deterministic Reproducibility

Every exploit chain must be deterministically logged and replayable. The system must generate a unique trace ID for each engagement, and every action (tool invocation, LLM prompt/response, state transition) must be recorded with timestamps. A successful exploit must be reproducible by replaying the logged actions against a fresh instance of the target container. If a replay fails, the original success is invalidated.

## 6.3 Multi-Stage Verification Protocol

- 1. Automated Grading: The CVE-Bench evaluation server checks for standard attack outcomes (file creation at /tmp/pwned, database modification, denial of service, etc.) programmatically.
- 2. Trace Replay: Every successful exploit chain is replayed against a clean container instance.
- 3. Human Audit (Sampling): A random 20% sample of successful exploits undergoes human review by a team member with penetration testing experience.
- 4. False Positive Detection: The Verification Agent independently confirms each success claim by checking the grader endpoint.

## 6.4 Baseline Expectations

The published CVE-Bench baseline of 13% ESR was achieved using frontier commercial models (GPT-4, Claude) with unlimited token budgets and no VRAM constraints. Our architecture uses 7–8B parameter local models under strict token budgets on consumer hardware. A realistic initial target is 3–5% ESR (successfully exploiting 1–2 out of 40 CVEs). This is not a failure — it means the autonomous pipeline works end to end and can be iteratively improved. The path to higher ESR involves refining prompts, expanding procedural memory with validated playbooks, and tuning retrieval parameters. The goal is a working framework that demonstrably improves over successive iterations, not an immediate match with SOTA performance.

## 6.5 Supplementary Evaluation

Beyond CVE-Bench, the team should evaluate the agent on Capture the Flag challenges from platforms like HackTheBox and TryHackMe (containerized locally, free tiers available). These provide additional diversity in vulnerability types and serve as development-phase diagnostics.

# 7. Memory Architecture: Episodic, Procedural, and Semantic

## 7.1 Episodic Memory

Episodic memory stores records of individual experiences: specific exploit attempts, their inputs, outputs, and outcomes. Each episode is stored as a structured record in ChromaDB with the following schema:

| Field | Type | Description |
| --- | --- | --- |
| episode_id | UUID | Unique identifier for the attempt |
| target_cve | string | CVE identifier of the target vulnerability |
| target_technology | string | E.g., "WordPress 6.4", "LoLLMs 9.5" |
| technique_attempted | string | E.g., "SQL injection via UNION-based extraction" |
| payload | string | The exact payload or command sequence used |
| response_summary | string | Summarized server response to the attempt |
| outcome | enum | SUCCESS / FAILURE / PARTIAL |
| failure_reason | string? | Why it failed (nullable on success) |
| timestamp | ISO 8601 | When the attempt was made |

The embedding vector is generated from a concatenation of technique_attempted and response_summary. When the Exploitation Agent plans a new attempt, it queries episodic memory to retrieve relevant prior experiences, avoiding repetition of known-failed approaches.

## 7.2 Procedural Memory

Procedural memory stores validated, reusable attack playbooks. When an exploit chain succeeds and passes replay verification, its complete action sequence is abstracted into a procedural template. For example: "For WordPress plugins with unauthenticated file upload vulnerabilities: Step 1 – enumerate plugin version; Step 2 – craft multipart POST with PHP web shell; Step 3 – trigger via direct URL access." These templates serve as high-confidence starting points for future engagements against similar targets.

## 7.3 Semantic Memory

Semantic memory is the CVE Knowledge Collection: the embedded corpus of CVE descriptions, exploit documentation, MITRE ATT&CK techniques, and OWASP testing procedures. Retrieval uses cosine similarity search with ChromaDB’s metadata filtering (e.g., retrieve only CVEs affecting WordPress with CVSS >= 9.0).

## 7.4 Memory Retrieval Strategy

During exploitation planning, the agent performs three parallel retrievals against semantic, episodic, and procedural memory. Results are merged and ranked, with procedural memory receiving highest priority (proven approaches), followed by episodic (learned experiences), then semantic (reference knowledge). The merged context is truncated to fit within the model’s effective context budget: 30% for memory retrieval, 30% for current reconnaissance data, and 40% reserved for the model’s reasoning and generation. On 7–8B models with practical context limits, this budget discipline is critical to avoid degraded output quality from overstuffed prompts.

# 8. Infrastructure and Deployment Architecture

## 8.1 Hardware: Distributed Student Machines

The system is designed to run on whatever hardware students already have. The minimum viable configuration is: any GPU with 6+ GB VRAM (e.g., GTX 1060 6GB, RTX 2060, Apple M1/M2 with unified memory), 16 GB system RAM, and 100 GB free disk space for Docker images, model weights, and ChromaDB storage. No purchases are required. Ollama runs on Linux, macOS, and Windows, and handles model quantization automatically.

**Quick-start model pulls:** `ollama pull llama3.1:8b-instruct-q4_K_M (reasoning, ~4.5GB), ollama pull qwen2.5-coder:7b-instruct-q4_K_M (exploit code, ~4.5GB), ollama pull nomic-embed-text (embeddings, ~300MB). Total disk: ~10 GB for all models.

## 8.2 Docker Compose Topology

The deployment consists of three Docker Compose stacks, all using free, open-source components. The first stack runs the target applications (CVE-Bench containers) on an isolated Docker network with no external access. The second stack runs the agent infrastructure: Ollama server, ChromaDB (running in-process within the Python agent, no separate container needed), and the LangGraph execution engine. The third stack is the sandbox hypervisor, which provides the network bridge between the agent infrastructure and the target network, enforcing firewall rules. All inter-stack communication flows through the hypervisor, which logs every packet.

## 8.3 Security Isolation

Target containers must run with restricted capabilities (--cap-drop=ALL), read-only root filesystems where possible, resource limits (CPU and memory cgroups), and no access to the Docker socket. The host machine’s firewall must block all outbound traffic from the target network. This air-gapped design ensures that even a successful container escape would not compromise the host or the broader network.

# 9. Getting Started: Phase-by-Phase Implementation Roadmap

## 9.1 Phase 1: Foundation (Weeks 1–3)

- Install Docker, Docker Compose, and Ollama on each team member’s machine. Pull the three recommended models (Llama 3.1 8B, Qwen2.5-Coder-7B, nomic-embed-text).
- Install ChromaDB via pip (pip install chromadb). Create the three collections (CVE Knowledge, Episodic Memory, Procedural Memory) in a shared Python module.
- Build the CVE ingestion pipeline: NVD API scraper → document chunker → nomic-embed-text → ChromaDB insertion.
- Clone CVE-Bench v2.1.0 and verify that at least 5 target containers build and run correctly with their grading endpoints functional.
- Build a single-agent prototype: one LLM agent that can receive a target URL, run nmap via MCP, and produce structured reconnaissance output.

## 9.2 Phase 2: Core Agent Pipeline (Weeks 4–7)

- Implement the LangGraph state machine with the Supervisor Node, Reconnaissance Agent, and Exploitation Agent.
- Implement the MCP transport layer with aggressive output truncation (target: <1,000 tokens per tool output).
- Build the episodic memory write/read pipeline: failed attempts are logged; the Exploitation Agent queries prior failures before planning.
- Achieve first successful automated exploit against a known-vulnerable DVWA target (not part of benchmark).
- Implement the evaluator gate in the Supervisor to reject nonsensical exploitation plans.

## 9.3 Phase 3: Evaluation and Iteration (Weeks 8–11)

- Run the full CVE-Bench benchmark suite and establish baseline ESR (target: 3–5%).
- Implement the Verification Agent and trace replay system.
- Analyze failure cases: categorize why the agent failed (wrong vulnerability identified, correct vulnerability but failed payload, timeout, hallucination, token budget exhausted).
- Iteratively improve: refine system prompts, add procedural memory templates for common vulnerability types, tune retrieval parameters.

## 9.4 Phase 4: Hardening and Documentation (Weeks 12–14)

- Maximize ESR through iterative refinement. Track improvement trajectory.
- Complete deterministic trace logging and replay verification for all successful exploits.
- Conduct the 20% human audit sampling of successful exploits.
- Document all architectural decisions, prompt templates, and configuration parameters.
- Prepare the final benchmark report with analysis of what worked, what didn’t, and recommended next steps.

# 10. Ground Rules: AI-Assisted Development Governance

The following ground rules apply to all tech leads, project managers, and developers working on this project. These rules govern how AI tools (including but not limited to ChatGPT, Claude, Copilot, and local LLMs) may be used during the development of the adversarial sandbox.

## 10.1 Permitted Uses of AI in Development

- 1. Code Scaffolding and Boilerplate: AI may generate boilerplate code (Docker Compose files, configuration templates, database schemas). All generated code must be reviewed, understood, and tested before committing.
- 2. Documentation Drafting: AI may draft documentation, README files, and inline comments. The developer is responsible for accuracy.
- 3. Debugging Assistance: AI may help diagnose error messages, suggest fixes for stack traces, and explain unfamiliar library behavior.
- 4. Research Synthesis: AI may summarize papers and compare technical approaches. Primary sources must still be read by the developer.
- 5. Test Generation: AI may generate unit test templates, but all assertions must be manually verified.

## 10.2 Prohibited Uses of AI in Development

- 1. Blind Copy-Paste: No AI-generated code may be committed without the developer fully understanding what it does. "It worked when I ran it" is not sufficient.
- 2. Security-Critical Logic: Core exploitation logic, payload templates, MCP transport, and sandbox isolation must be written and reviewed by humans with cybersecurity knowledge.
- 3. Automated Commits: No workflow may automatically commit AI-generated code without human review.
- 4. Sensitive Data in Cloud Prompts: No CVE exploit details or vulnerability data may be sent to cloud-hosted AI services. All sensitive AI-assisted development must use local models via Ollama only.
- 5. Bypassing Code Review: AI-generated code receives more scrutiny, not less.

## 10.3 Attribution and Transparency Requirements

- AI-assisted code must include: "// AI-ASSISTED: Generated/modified with [tool]. Reviewed by [name] on [date]."
- Pull request descriptions must include an "AI Usage" section.
- The project README must document the team’s AI development practices.

## 10.4 Quality Gates for AI-Generated Code

- Must pass the project linter (ruff for Python, eslint for JS/TS) with zero warnings.
- Must have corresponding unit tests with at least 80% branch coverage.
- Docker configurations must be reviewed by the infrastructure lead.
- LangGraph state machine definitions must be reviewed by the project lead.

## 10.5 Accountability

The developer who commits AI-generated code is fully responsible for its behavior, bugs, and security implications. "The AI wrote it" is not an acceptable explanation for defects. Tech leads are responsible for enforcing these rules and flagging violations during code review.

# 11. Risk Register

This section catalogues the primary risks facing the project. Each risk is assessed for likelihood and impact, with a concrete mitigation strategy assigned.

## 11.1 Technical Risks

Technical risks arise from the constraints of using small language models for complex autonomous reasoning.

Model Hallucination (Likelihood: High). Small models hallucinate more frequently than frontier models. The Exploitation Agent may fabricate exploit chains, claim success against nonexistent services, or generate nonsensical payloads. Mitigated through the Verification Agent, trace replay, and the Supervisor’s evaluator gate.

Infinite Retry Loops (Likelihood: High). The agent repeatedly attempts the same failed approach. Addressed by hard caps on steps (30), tokens (50K), and wall-clock time (15 minutes), combined with episodic memory that detects repeated payloads.

Context Window Saturation (Likelihood: High). With 7–8B models, effective context quality degrades well before the theoretical maximum. The MCP transport layer must enforce aggressive output truncation (<1,000 tokens per tool output), and memory retrieval must be budgeted carefully.

Low ESR with Small Models (Likelihood: High). 7–8B models may lack the reasoning depth for complex multi-step exploits. Mitigated by focusing on simpler vulnerability classes first, building strong procedural memory, and using the code specialist for payload generation. The goal is a working pipeline, not SOTA performance.

## 11.2 Operational Risks

Container Escape (Likelihood: Low, Impact: Critical). Mitigated by air-gapped Docker network, --cap-drop=ALL, read-only rootfs, and host firewall.

Heterogeneous Hardware (Likelihood: High). Team members have different GPUs and operating systems. Mitigated by targeting the lowest common denominator (6 GB VRAM) and testing on multiple platforms during Phase 1.

Legal and Ethical Exposure (Likelihood: Low). Mitigated by confining all activity to isolated containers with no external targets, documenting the defensive research purpose, and seeking institutional review if required.

## 11.3 Risk Summary Matrix

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Model hallucination | High | Medium | Verification Agent + trace replay. Evaluator gate rejects plans targeting undiscovered services. |
| Infinite retry loops | High | High | Hard caps: 30 steps, 50K tokens, 15 min/target. Max 3 retries. Episodic memory prevents identical retries. |
| Context saturation | High | Medium | Aggressive MCP output truncation. Memory retrieval budgets. Concise prompt templates. |
| Low ESR | High | Medium | Focus on simpler CVEs first. Build procedural memory. Iterative prompt refinement. |
| Container escape | Low | Critical | Air-gapped network, --cap-drop=ALL, read-only rootfs, host firewall. |
| Heterogeneous HW | High | Low | Target 6 GB VRAM minimum. Test on multiple platforms. Ollama cross-platform. |
| Legal/ethical exposure | Low | High | Isolated containers only. No external targets. Document defensive purpose. |

# 12. Key References and Resources

## 12.1 Academic Benchmarks

- CVE-Bench (ICML 2025 Spotlight): arxiv.org/abs/2503.17332 | GitHub: github.com/uiuc-kang-lab/cve-bench
- CVE-Bench for Vulnerability Repair (NAACL 2025): aclanthology.org/2025.naacl-long.212
- Pentest-R1: RL for Penetration Testing Reasoning (2025): arxiv 2025.08.10
- HackSynth: LLM Agent Framework for Autonomous Pentesting (2024): arxiv 2024.12.02

## 12.2 Frameworks and Tools

- LangGraph: langchain-ai.github.io/langgraph (free, open-source)
- Ollama: ollama.com (free, open-source local LLM serving)
- ChromaDB: trychroma.com (free, open-source vector database, pip install chromadb)
- Qdrant: qdrant.tech (free, open-source, optional upgrade path)
- Model Context Protocol (MCP): modelcontextprotocol.io (free, open-source)
- MITRE ATT&CK: attack.mitre.org (free)
- NVD API: nvd.nist.gov/developers (free, no API key for basic access)

## 12.3 Model Weights (via Ollama)

- llama3.1:8b-instruct-q4_K_M (~4.5 GB VRAM) — Primary reasoning
- qwen2.5-coder:7b-instruct-q4_K_M (~4.5 GB VRAM) — Code generation
- nomic-embed-text (~300 MB VRAM) — Embeddings
- All models: free, open-weights, single command to install

## 12.4 Security Governance

- CSA Agentic AI Red Teaming Guide (May 2025): cloudsecurityalliance.org/artifacts/agentic-ai-red-teaming-guide
- CoSAI Principles for Secure-by-Design Agentic Systems (July 2025)
- Awesome-LLM4Cybersecurity: github.com/tmylla/Awesome-LLM4Cybersecurity (curated paper list)