**Dynamic Patch Generation via Autonomous Defense Multi-Agent Systems**

*Technical Architecture, Model Selection, Datasets, Reward Functions, Validation Strategies, and AI Development Governance*

**CONFIDENTIAL — INTERNAL USE ONLY** | March 2026 | Version 1.0

# 1. Executive Overview and Research Scope

This research report provides the comprehensive technical blueprint for building the Blue Team (defense) agent within the Adversarial Cybersecurity Sandbox for Dynamic Vulnerability Exploitation. The Blue Team agent is the defensive core of the system: an autonomous, multi-agent pipeline that monitors system logs, reverse-engineers active exploitation paths, and dynamically generates and deploys neutralizing code-level patches against Dockerized web applications — all without human guidance.

The defense agent architecture must accomplish three fundamental objectives. First, it must monitor system logs, network traffic, and application behavior in real time to detect when the Red Team agent has successfully exploited a vulnerability. Second, it must analyze the exploitation path — understanding what the attacker did, which vulnerability was exploited, and how the payload achieved its goal — by reverse-engineering the attack chain from observable evidence. Third, it must autonomously generate, validate, and deploy a code-level patch or configuration change that neutralizes the specific vulnerability without breaking the application's intended functionality.

The guiding principle of this project is a working, zero-budget, fully open-source framework. Every component — models, vector databases, orchestration tools, and target environments — must run on distributed student hardware at zero cost with no paid cloud services, no commercial API subscriptions, and no licensed software. All models must fit within approximately 6 GB of VRAM using consumer-grade GPUs that students already own. The architecture is designed to be practical and functional first; performance optimization comes after the pipeline works end to end.

Current academic research shows that automated vulnerability repair is a rapidly evolving field. CVE-Bench (NAACL 2025) demonstrates that LLM agents using SWE-agent can repair approximately 21% of real-world CVE vulnerabilities at best with frontier models. PatchEval (2025) shows the best-performing approach achieves only 23% success rate in patch generation. Our architecture uses 7–8B parameter local models under strict token budgets on consumer hardware, so realistic initial expectations must be calibrated accordingly — the goal is a working defense pipeline that can patch at least some vulnerabilities the Red Team exploits, then iteratively improve.

The scope of this report is deliberately constrained to the Blue Team agent. The Red Team (adversarial) agent is covered in a companion document. Both agents operate concurrently within the same sandbox, forming the complete Attack & Defense (A&D) system described in the original proposal.

---

# 2. Model Selection Strategy

## 2.1 The Local-First, Zero-Budget Constraint

All constraints from the Red Team report apply identically: all inference must run on local, air-gapped student hardware using open-weights models served through Ollama at zero cost. Commercial APIs are excluded for the same two reasons: safety filters would interfere with analyzing exploit payloads, and sending live attack logs to cloud endpoints creates data exfiltration risk. Models must fit within 6–8 GB of VRAM on whatever GPUs students already own (GTX 1060 6GB, RTX 2060, RTX 3060, Apple M-series).

## 2.2 Recommended Model Stack (≤6 GB VRAM)

The Blue Team agent requires three distinct cognitive capabilities: log analysis and attack reconstruction (understanding what the Red Team did from system evidence), vulnerability root-cause analysis (identifying why the exploit worked), and patch code generation (writing the fix). The same SLMs used by the Red Team serve the Blue Team.

### 2.2.1 Primary Reasoning and Analysis Engine

**Llama 3.1 8B Instruct** is the recommended primary model. At 4-bit quantization (~4.5 GB VRAM), it handles log analysis, attack chain reconstruction, and vulnerability root-cause reasoning. Its 128K context window is critical for ingesting lengthy log files and application source code simultaneously. Alternatives: Qwen2.5-7B-Instruct, Mistral 7B Instruct v0.3.

### 2.2.2 Code Generation and Patching Specialist

**Qwen2.5-Coder-7B-Instruct** is the recommended code generation model for writing patches. Apache 2.0 license, ~4.5 GB VRAM, no API key required. This model generates configuration patches, code fixes, WAF rules, and input validation logic. Alternative: CodeLlama 7B Instruct. On limited VRAM, the reasoning model can handle patching as well — the specialist is an optimization, not a requirement.

### 2.2.3 Practical Deployment: Shared Models with Red Team

Both the Red Team and Blue Team use the same model weights — they do not need separate copies. Ollama serves models to both agent pipelines. On a single machine, only one model can be loaded at a time (Ollama auto-swaps, 10–30 second latency). If the Red and Blue agents run on separate machines in the student cluster, both can load models simultaneously.

## 2.3 Model Configuration via Ollama

Temperature: 0.1–0.2 for patch generation (correctness is paramount — a bad patch breaks the application), 0.3–0.5 for log analysis and attack reconstruction (some interpretive flexibility is useful). Context budget is even more critical for the Blue Team because it must simultaneously hold: the attack evidence (logs, HTTP requests), the vulnerable source code, CVE documentation, and prior patch memory. The Supervisor enforces strict per-engagement token caps (50K tokens). Top-p: 0.9. Repeat penalty: 1.1.

## 2.4 Model Comparison Matrix

| Model | Params | VRAM (4-bit) | Role | Context | License |
| --- | --- | --- | --- | --- | --- |
| Llama 3.1 8B Instruct | 8B | ~4.5 GB | Log Analysis / Reasoning | 128K | Llama 3.1 |
| Qwen2.5-Coder-7B-Instruct | 7B | ~4.5 GB | Patch Generation | 128K | Apache 2.0 |
| Qwen2.5-7B-Instruct | 7B | ~4.5 GB | Alt. Reasoning | 128K | Apache 2.0 |
| CodeLlama 7B Instruct | 7B | ~4.5 GB | Alt. Patching | 16K | Llama 2 |
| Mistral 7B Instruct v0.3 | 7B | ~4.5 GB | Alt. Reasoning | 32K | Apache 2.0 |
| nomic-embed-text | 137M | ~0.3 GB | Embeddings | 8K | Apache 2.0 |

All models are identical to the Red Team stack. Total cost: $0. Total additional disk: 0 GB (shared weights).

---

# 3. Databases, Datasets, and Knowledge Architecture

## 3.1 CVE Patch Knowledge Base

The Blue Team's foundational dataset is the remediation side of the NVD: for every CVE, the associated patch commits, security advisories, and remediation guidance. The team should build an automated ingestion pipeline that, for each CVE in the knowledge base, extracts: the official patch diff (from GitHub/GitLab commit links in the NVD advisory), the CWE classification (which determines the class of fix — input validation, access control, bounds checking, etc.), and any vendor-provided remediation guidance. Sources: NVD API (free), GitHub (free), Exploit-DB patch references (free).

## 3.2 Secure Coding and Remediation Corpus

Beyond NVD patches, the knowledge base should ingest: OWASP Secure Coding Practices Quick Reference Guide (free), CWE Top 25 remediation guidance (free, from MITRE), SANS Secure Coding guidelines (publicly available summaries), and technology-specific hardening guides (WordPress hardening, Apache/nginx security configuration, PHP security best practices). All chunked to preserve code examples, configuration snippets, and step-by-step remediation procedures.

## 3.3 Target Environment Dataset

The Blue Team operates on the same CVE-Bench v2.1.0 target containers as the Red Team. Each container includes the vulnerable application source code (accessible to the Blue Team for analysis and patching), system logs and access logs, and the CVE-Bench grader endpoint (which the Blue Team uses to verify that its patch neutralizes the vulnerability). Supplementary targets: DVWA (free), WebGoat (free), VulnHub (free) — identical to Red Team development targets.

## 3.4 Vector Database: ChromaDB (Zero-Cost)

ChromaDB is the vector database, identical to Red Team. Three Blue Team-specific collections:

1. **Patch Knowledge Collection** — embedded patch diffs, remediation procedures, and secure coding patterns indexed by CWE type, affected technology, and vulnerability class.
2. **Defensive Episodic Memory** — records of prior patching attempts (both successful and failed) indexed by vulnerability type, patch strategy, and outcome.
3. **Defensive Procedural Memory** — validated, reusable patching playbooks (e.g., "For SQL injection in PHP applications: Step 1 — identify unsanitized input parameter; Step 2 — apply prepared statement pattern; Step 3 — validate patch does not break existing queries").

ChromaDB: `pip install chromadb`, zero cost, no server needed.

## 3.5 Embedding Model Selection

**nomic-embed-text** via Ollama. Same embedding model as Red Team. ~300 MB VRAM. Consistent embeddings across all collections (Red Team and Blue Team share the same embedding space, enabling cross-team memory queries in future iterations).

---

# 4. Multi-Agent Architecture and LangGraph Orchestration

## 4.1 Agent Architecture: More Than Just an LLM

The same principle applies to every Blue Team agent: the agent is the full wrapper, not the LLM. Each Blue Team agent includes:

**Prompt Engineering Layer.** Every agent operates from carefully engineered system prompts. The Patch Generation Agent's prompt, for example, must instruct it to always reference the specific CWE remediation pattern, always produce a minimal diff (smallest possible code change), and never modify functionality unrelated to the vulnerability.

**Rules and Guardrails ("Bible").** Hard-coded behavioral rules enforced programmatically: never modify code outside the vulnerable function/file, never generate patches that disable security features (e.g., turning off WAF rules instead of fixing the underlying code), never deploy a patch that fails functional tests, always log the complete reasoning chain before modifying any file.

**Scoping and Context Management.** Each agent has strict scope: the Log Analysis Agent only sees logs and returns structured attack summaries — it never sees source code. The Patch Generation Agent receives the vulnerability analysis and relevant source code, but never sees raw logs. Context is assembled programmatically within token budgets.

**Confidence Intervals and Self-Assessment.** Each agent outputs a confidence score (0.0–1.0). The Patch Generation Agent must rate its confidence that a proposed patch is correct and will not break the application. Patches with confidence below 0.6 are flagged for additional memory retrieval or alternative strategy generation rather than blind deployment.

**Token Usage Metrics and Budget Tracking.** Every agent tracks token consumption and reports to the Supervisor. Running token ledger per engagement with 50K cap enforced.

**Output Validation and Parsing.** Patch output must be valid unified diff format. Wrapper validates syntax, checks that modified files exist, and rejects malformed patches before deployment.

## 4.2 Agent Hierarchy

The Blue Team system consists of four specialized agents coordinated by a LangGraph Supervisor Node.

### 4.2.1 Supervisor Node (Defensive Command)

Central router for the defense pipeline. Receives alerts from the Red Team's activity (either via the sandbox hypervisor's packet logs or via the CVE-Bench grader detecting a successful exploit). The Supervisor enforces hard caps: 30 steps, 50K tokens, 15 minutes per vulnerability. Routes tasks between the Log Analysis Agent, Root Cause Agent, Patch Generation Agent, and Patch Validation Agent.

### 4.2.2 Log Analysis Agent

Monitors system logs, HTTP access logs, error logs, and network packet captures from the sandbox hypervisor. When it detects anomalous activity or receives an alert that the Red Team has successfully exploited a target, it reconstructs the attack chain from observable evidence: which endpoint was targeted, what payload was sent, what the server's response was, and which CVE-Bench attack goal was achieved. Outputs a structured Attack Summary (JSON) for the Root Cause Agent.

### 4.2.3 Root Cause Agent

Receives the Attack Summary and the vulnerable application's source code. Analyzes why the exploit succeeded: identifies the specific vulnerable code path, the CWE classification (e.g., CWE-89 SQL Injection, CWE-22 Path Traversal), the missing security control (e.g., no input sanitization, no access check), and the minimal code location that needs modification. Queries the Patch Knowledge Collection in ChromaDB for relevant remediation patterns. Outputs a structured Vulnerability Analysis (JSON) for the Patch Generation Agent.

### 4.2.4 Patch Generation Agent

The cognitive core of the Blue Team. Receives the Vulnerability Analysis, the relevant source code files, and retrieved remediation patterns from procedural memory. Generates a code-level patch as a unified diff. The patch must be minimal (smallest possible change), correct (fixes the vulnerability), and non-breaking (does not alter intended application behavior). Uses Qwen2.5-Coder-7B for code generation, falling back to Llama 3.1 8B on constrained hardware.

### 4.2.5 Patch Validation Agent

After the Patch Generation Agent produces a patch, the Validation Agent independently tests it. Applies the patch to a fresh copy of the target container, runs the application's existing functionality checks (if available), then re-runs the Red Team's exploit chain (from the trace log) against the patched application. If the exploit still succeeds, the patch is rejected and the cycle restarts with updated memory. If the exploit fails and the application still functions correctly, the patch is confirmed.

## 4.3 State Machine and Graph Topology

**Core Flow:** RED TEAM EXPLOIT DETECTED → Log Analysis → Supervisor (evaluate attack summary) → Root Cause Analysis → Supervisor (evaluate vulnerability analysis) → Patch Generation → Supervisor (evaluate patch) → Patch Validation → either PATCH CONFIRMED (if exploit blocked + app functional) or back to Patch Generation (if patch failed, max 3 retries)

The Supervisor tracks a retry counter per vulnerability and enforces a maximum of 3 patching attempts. If all 3 fail, the vulnerability is marked as unresolved and logged for human review.

## 4.4 MCP Transport Layer

MCP serves the same role as in the Red Team: transporting data between the isolated Docker containers and the LangGraph execution engine. For the Blue Team, MCP additionally handles: reading application source code from target containers (read-only access), applying patches to target containers (write access limited to specific file paths), and collecting post-patch test results. Aggressive output truncation applies: log files can exceed 50,000 tokens, so MCP must extract only the relevant log entries (time-windowed around the detected exploit, filtered by target endpoint).

## 4.5 Red–Blue Coordination Protocol

The Red and Blue Teams operate concurrently but with defined interaction rules:

1. **Sequential by default:** The Red Team attacks first. When a successful exploit is detected (via CVE-Bench grader), the Blue Team is activated for that specific vulnerability.
2. **No information leakage:** The Blue Team does not receive the Red Team's internal reasoning, prompts, or strategy. It only receives what is externally observable: system logs, network traffic, HTTP requests/responses, and the CVE-Bench grader result.
3. **Patch deployment triggers re-test:** After the Blue Team deploys a patch, the Red Team's original exploit chain is replayed against the patched application to verify neutralization.
4. **Shared memory (future):** In future iterations, the Blue Team's successful patches can be fed back to the Red Team as adversarial challenges ("can you bypass this patch?"), creating an evolutionary arms race. This is out of scope for the initial implementation.

---

# 5. Reward Function Design

## 5.1 Why a Reward Function Matters

Same principle as Red Team: the reward function measures whether the defense system is improving across iterations and provides structured feedback for the Supervisor's routing decisions. The Blue Team's reward function is evaluated independently from the Red Team's.

## 5.2 Primary Reward: Patch Success Rate (PSR)

The primary reward signal is binary per vulnerability: 1 if the Blue Team's patch successfully neutralizes the exploit (Red Team's exploit chain fails against patched application) AND the application remains functional, 0 otherwise. PSR = successful_patches / total_vulnerabilities_attempted.

## 5.3 Secondary Rewards: Multi-Dimensional Scoring

| Metric | Weight | Description | Calculation |
| --- | --- | --- | --- |
| Patch Success Rate | 0.35 | Binary: did the patch neutralize the exploit? | successful_patches / total_attempted |
| Patch Minimality | 0.15 | Size of the patch relative to the codebase | 1 - (lines_changed / total_lines_in_file) |
| Time-to-Patch (TTP) | 0.15 | Speed from exploit detection to successful patch | 1 - (time_taken / max_time) |
| Functional Preservation | 0.15 | Application still works after patching | functional_tests_passed / total_functional_tests |
| Efficiency Score | 0.10 | Success relative to tokens consumed | successful_patches / total_tokens_used |
| Grounding Penalty | -0.10 | Patches that modify code unrelated to the vulnerability | -1 × (ungrounded_changes / total_changes) |

**Note on Patch Minimality:** A good patch is the smallest possible change that fixes the vulnerability. Large, sweeping patches are more likely to introduce regressions and indicate the agent doesn't understand the root cause. This metric incentivizes surgical fixes.

**Note on the Grounding Penalty:** Same principle as the Red Team: you cannot tell the LLM "don't hallucinate a fix." Instead, the wrapper programmatically verifies that every code change in the patch touches a file/function identified in the Vulnerability Analysis. If the patch modifies code outside the identified vulnerable path, the wrapper flags it as an ungrounded change. This is computed externally from factual source code analysis, not from the model's self-assessment, and cannot be gamed.

## 5.4 Composite Reward Formula

The composite reward R for a single evaluation run is:

> **R = 0.35(PSR) + 0.15(minimality) + 0.15(TTP) + 0.15(functional_preservation) + 0.10(efficiency) – 0.10(grounding_penalty)**
> 

## 5.5 Anti-Exploitation of Reward Weights

Same principle as Red Team: the reward function is computed entirely outside the LLM's awareness. The LLM never sees the composite score or weights. All metrics are computed from externally verifiable facts:

- **PSR** is determined by replaying the Red Team's exploit against the patched container — the Blue Team LLM cannot manipulate the replay.
- **Minimality** is computed by diffstat on the actual patch, not by the model's claim of patch size.
- **Functional preservation** is computed by running actual tests against the patched container.
- **Grounding penalty** is computed by the wrapper's source code analyzer comparing patch scope against the Vulnerability Analysis output.

## 5.6 Intra-Engagement Feedback Signals

Successful log analysis that correctly identifies the exploited endpoint: +2. Correct CWE classification: +2. Patch that compiles/applies cleanly: +1. Patch that passes functional tests: +3. Patch that blocks the exploit: +10. Patch that fails to apply: -2. Patch that breaks the application: -5. These guide the Supervisor's routing decisions within a single engagement.

---

# 6. Validation and Correctness Testing

## 6.1 Dual Validation: Functional + Security

Unlike the Red Team (which only needs to prove an exploit works), the Blue Team must pass two independent validation checks: the patch must block the exploit (security validation) AND the application must continue working correctly (functional validation). A patch that blocks an exploit by crashing the application is not a success.

## 6.2 Deterministic Reproducibility

Every patch chain must be deterministically logged and replayable. The system generates a unique trace ID for each defense engagement. Every action (log retrieval, LLM prompt/response, root cause analysis, patch generation, test results) is recorded with timestamps. A successful patch must be reproducible by replaying the logged actions against a fresh instance of the target container.

## 6.3 Multi-Stage Verification Protocol

1. **Patch Application Test** — Does the patch apply cleanly to the target container without syntax errors or conflicts?
2. **Functional Test** — Does the application still serve its intended purpose after patching? (HTTP health checks, basic functionality verification)
3. **Security Test (Exploit Replay)** — Does the Red Team's original exploit chain fail against the patched application?
4. **Regression Test** — Does the patch introduce any new vulnerabilities? (Basic static analysis scan of the patched code)
5. **Human Audit (Sampling)** — A random 20% sample of successful patches undergoes human review to verify the fix addresses the actual root cause rather than masking symptoms.

## 6.4 Baseline Expectations

CVE-Bench for Vulnerability Repair (NAACL 2025) shows SWE-agent with GPT-4 achieves approximately 21% repair rate. PatchEval (2025) shows the best approach achieves 23%. These results use frontier commercial models with unlimited budgets. Our architecture uses 7–8B local models under strict token budgets. A realistic initial target is 5–10% PSR (successfully patching 1–2 out of the vulnerabilities the Red Team exploits). This is not a failure — it means the autonomous defense pipeline works end to end. Improvement comes through iterative prompt refinement, expanded procedural memory with validated patch templates, and better root cause analysis prompts.

## 6.5 Supplementary Evaluation

Beyond patching Red Team exploits, the Blue Team should be tested on known CVE patches from the NVD: given the vulnerability description and the vulnerable source code, can it independently generate a patch that matches (or is functionally equivalent to) the official developer fix? This provides a larger evaluation corpus independent of the Red Team's success rate.

---

# 7. Memory Architecture: Episodic, Procedural, and Semantic

## 7.1 Episodic Memory

Each defense episode is stored in ChromaDB:

| Field | Type | Description |
| --- | --- | --- |
| episode_id | UUID | Unique identifier for the patching attempt |
| target_cve | string | CVE identifier of the exploited vulnerability |
| target_technology | string | E.g., "WordPress 6.4", "LoLLMs 9.5" |
| attack_summary | string | How the Red Team exploited the vulnerability |
| cwe_classification | string | E.g., "CWE-89: SQL Injection" |
| patch_strategy | string | E.g., "Replace string concatenation with prepared statements" |
| patch_diff | string | The actual unified diff of the attempted patch |
| outcome | enum | SUCCESS / FAILURE / REGRESSION |
| failure_reason | string? | Why the patch failed (nullable on success) |
| timestamp | ISO 8601 | When the attempt was made |

Embedding: concatenation of cwe_classification + patch_strategy + failure_reason. Queries: "have I tried patching this type of vulnerability before? What worked? What didn't?"

## 7.2 Procedural Memory

Validated patching playbooks abstracted from successful defense engagements. Example: "For CWE-89 SQL Injection in PHP applications: Step 1 — identify the unsanitized user input flowing into the SQL query; Step 2 — replace string concatenation with PDO prepared statements; Step 3 — add input type validation as defense-in-depth; Step 4 — verify query still returns expected results." Stored with metadata: CWE type, affected technology, language, success count.

## 7.3 Semantic Memory

The Patch Knowledge Collection: embedded corpus of official CVE patches, OWASP remediation guidance, CWE-specific fix patterns, and secure coding references. Retrieval uses cosine similarity with metadata filtering (e.g., retrieve only CWE-89 patches for PHP applications).

## 7.4 Memory Retrieval Strategy

Same as Red Team: three parallel retrievals (procedural > episodic > semantic). Budget: 30% memory, 30% attack evidence + source code, 40% reasoning. On 7–8B models, careful context management is critical.

---

# 8. Infrastructure and Deployment Architecture

## 8.1 Hardware: Distributed Student Machines

Identical to Red Team: any GPU with 6+ GB VRAM, 16 GB RAM, 100 GB disk. No purchases required. Same Ollama model weights — no additional disk needed.

**Quick-start:** Same models as Red Team. `ollama pull llama3.1:8b-instruct-q4_K_M`, `ollama pull qwen2.5-coder:7b-instruct-q4_K_M`, `ollama pull nomic-embed-text`. If Red Team is already set up, Blue Team requires zero additional model downloads.

## 8.2 Docker Compose Topology

The Blue Team adds to the existing three-stack architecture:

- **Stack 1 (Target apps):** Same CVE-Bench containers. Blue Team gets read access to source code and write access to apply patches.
- **Stack 2 (Agent infra):** Adds Blue Team LangGraph pipeline alongside Red Team. Both use the same Ollama server and ChromaDB instance (separate collections).
- **Stack 3 (Sandbox hypervisor):** Extended to relay exploit detection events to the Blue Team Supervisor and to manage "patched container" instances for validation.

All additional components are free and open-source. No new infrastructure costs.

## 8.3 Security Isolation

Same constraints as Red Team: --cap-drop=ALL, read-only rootfs (except for patch deployment paths), resource limits, no Docker socket access, host firewall blocks outbound. The Blue Team's write access to target containers is strictly scoped: it can only modify files identified in the Vulnerability Analysis output, and only through the MCP transport layer which enforces path whitelisting.

---

# 9. Getting Started: Phase-by-Phase Implementation Roadmap

## 9.1 Phase 1: Foundation (Weeks 1–3)

- Extend the existing Ollama + ChromaDB setup with three Blue Team collections (Patch Knowledge, Defensive Episodic, Defensive Procedural).
- Build the patch ingestion pipeline: NVD advisory scraper → GitHub patch diff extractor → CWE classifier → embedder → ChromaDB.
- Build the Log Analysis Agent prototype: ingest sample access logs from DVWA and identify known attack patterns (SQL injection strings, directory traversal paths).
- Verify Blue Team can read source code from CVE-Bench containers via MCP.

## 9.2 Phase 2: Core Agent Pipeline (Weeks 4–7)

- Implement the Blue Team LangGraph state machine with Supervisor, Log Analysis, Root Cause, and Patch Generation agents.
- Implement the MCP extensions for source code reading and patch deployment.
- Build the defense episodic memory pipeline: failed patches are logged; the Patch Generation Agent queries prior failures before generating.
- Achieve first successful automated patch against a known-vulnerable DVWA target.
- Implement the Red–Blue coordination protocol: Red Team exploit → Blue Team alert → patch → replay.

## 9.3 Phase 3: Evaluation and Iteration (Weeks 8–11)

- Run combined Red + Blue against CVE-Bench. Measure PSR on vulnerabilities the Red Team successfully exploits.
- Implement the Patch Validation Agent and exploit replay system.
- Analyze failure cases: wrong root cause identified, correct root cause but bad patch, patch breaks application, patch doesn't fully fix the vulnerability.
- Iteratively improve: refine system prompts, add procedural memory templates for common CWE types, tune retrieval.

## 9.4 Phase 4: Hardening and Documentation (Weeks 12–14)

- Maximize PSR through iterative refinement. Track improvement trajectory.
- Complete deterministic trace logging and replay verification for all successful patches.
- Conduct 20% human audit of successful patches.
- Test Blue Team independently on NVD patch generation (without Red Team).
- Document all architectural decisions, prompt templates, and configuration.
- Prepare final benchmark report.

---

# 10. Ground Rules: AI-Assisted Development Governance

All governance rules from the Red Team report apply identically to the Blue Team development. In summary:

## 10.1 Permitted Uses of AI in Development

1. Code scaffolding/boilerplate (must review before commit)
2. Documentation drafting (developer responsible for accuracy)
3. Debugging assistance
4. Research synthesis (must read primary sources)
5. Test generation (verify all assertions)

## 10.2 Prohibited Uses of AI in Development

1. Blind copy-paste without understanding
2. Security-critical logic without human expert approval (this is especially important for the Blue Team — a bad patch IS a security vulnerability)
3. Automated commits without review
4. Sensitive data in cloud AI prompts (use local Ollama only)
5. Bypassing code review

## 10.3 Attribution and Transparency Requirements

- Comment: `// AI-ASSISTED: Generated with [tool]. Reviewed by [name] on [date].`
- PR descriptions must include "AI Usage" section
- README must document AI development practices

## 10.4 Quality Gates for AI-Generated Code

- Pass linter with zero warnings
- 80% branch coverage for AI-generated functions
- Infrastructure lead reviews Docker configs
- Project lead reviews LangGraph state machines
- **Blue Team specific:** All patch generation logic must be reviewed by a team member with secure coding knowledge

## 10.5 Accountability

Developer who commits AI code owns all bugs. "The AI wrote it" is not acceptable. For Blue Team specifically: a patch that introduces a new vulnerability is a critical failure that must be root-caused and documented.

---

# 11. Risk Register

## 11.1 Technical Risks

**Patch Hallucination (Likelihood: High).** Small models may generate patches that look plausible but do not actually fix the vulnerability, or that fix the wrong code location. Mitigated by the agent wrapper validating every patch change against the Root Cause Agent's Vulnerability Analysis, the Grounding Penalty metric, and the Patch Validation Agent's exploit replay.

**Regression Introduction (Likelihood: High).** Patches may break application functionality. Mitigated by mandatory functional testing before patch deployment, the Functional Preservation metric, and hard rejection of patches that fail health checks.

**Context Window Saturation (Likelihood: High).** Blue Team context demands are higher than Red Team because it must hold attack evidence + source code + CVE data + patch memory simultaneously. Mitigated by aggressive MCP truncation of logs (<1,000 tokens), targeted source code extraction (only vulnerable files, not entire codebase), and strict memory retrieval budgets.

**Insufficient Attack Evidence (Likelihood: Medium).** If the Red Team's exploit leaves minimal log traces, the Blue Team may not have enough evidence to reconstruct the attack. Mitigated by using the sandbox hypervisor's packet capture as a supplementary evidence source, and by querying the CVE-Bench grader for the specific attack goal achieved.

## 11.2 Operational Risks

**Container Escape (Likelihood: Low, Impact: Critical).** Same mitigations as Red Team: air-gapped network, --cap-drop=ALL, read-only rootfs, host firewall.

**Heterogeneous Hardware (Likelihood: High).** Same mitigation: target 6 GB VRAM minimum, test on multiple platforms.

**Red–Blue Synchronization (Likelihood: Medium).** Timing issues between Red Team exploitation and Blue Team response. Mitigated by event-driven architecture: Blue Team activates only on confirmed exploit detection, not on a timer.

## 11.3 Risk Summary Matrix

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Patch hallucination | High | High | Wrapper validates patch scope against root cause. Grounding penalty. Exploit replay. |
| Regression introduction | High | High | Mandatory functional tests. Functional preservation metric. Health checks. |
| Context saturation | High | Medium | MCP log truncation. Targeted source extraction. Memory budgets. |
| Insufficient evidence | Medium | Medium | Packet capture supplement. CVE-Bench grader query. Multi-source evidence. |
| Container escape | Low | Critical | Air-gapped, --cap-drop=ALL, rootfs, firewall. |
| Heterogeneous HW | High | Low | 6 GB VRAM target. Cross-platform testing. |
| Red–Blue sync | Medium | Low | Event-driven activation. Confirmed exploit trigger only. |

---

# 12. Key References and Resources

## 12.1 Academic Benchmarks

- CVE-Bench for Vulnerability Repair (NAACL 2025): aclanthology.org/2025.naacl-long.212 — SWE-agent achieves ~21% repair rate
- PatchEval (2025): arxiv.org/abs/2511.11019 — 1,000 CVEs, best approach achieves 23% patch success
- PatchIsland: Orchestration of LLM Agents for Continuous Vulnerability Repair (2025): arxiv.org/abs/2601.17471
- LLM4CVE: Iterative Automated Vulnerability Repair (2025): arxiv 2025.01.07
- ZeroDayBench: Evaluating LLM Agents on Zero-Day Vulnerabilities for Cyberdefense (2026): arxiv.org/abs/2603.02297
- CVE-Bench for Exploitation (ICML 2025): arxiv.org/abs/2503.17332 | github.com/uiuc-kang-lab/cve-bench

## 12.2 Frameworks and Tools (All Free)

- LangGraph: langchain-ai.github.io/langgraph
- Ollama: ollama.com
- ChromaDB: trychroma.com (`pip install chromadb`)
- Model Context Protocol (MCP): modelcontextprotocol.io
- OWASP Secure Coding Practices: owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- CWE Top 25: cwe.mitre.org/top25/
- MITRE ATT&CK: attack.mitre.org
- NVD API: nvd.nist.gov/developers

## 12.3 Model Weights (via Ollama)

- `llama3.1:8b-instruct-q4_K_M` (~4.5 GB) — Primary reasoning and log analysis
- `qwen2.5-coder:7b-instruct-q4_K_M` (~4.5 GB) — Patch code generation
- `nomic-embed-text` (~300 MB) — Embeddings
- All free, open-weights, shared with Red Team (zero additional download if Red Team already set up)

## 12.4 Security Governance

- CSA Agentic AI Red Teaming Guide (May 2025): cloudsecurityalliance.org/artifacts/agentic-ai-red-teaming-guide
- CoSAI Principles for Secure-by-Design Agentic Systems (July 2025)
- Awesome-LLM4Cybersecurity: github.com/tmylla/Awesome-LLM4Cybersecurity