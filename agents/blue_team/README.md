# /agents/blue_team — Blue Team Agent Pipeline

**OWNER: Blue Team Hire(s)**  
**PHASE: 2**  
**READ FIRST: `/docs/blue_team_report.md`**

---

## Your Pipeline

```
RED TEAM EXPLOIT DETECTED (from hypervisor event)
  └─→ log_analysis_agent.py      ← reconstruct attack from logs
        └─→ supervisor.py        ← evaluate attack summary
              └─→ root_cause_agent.py  ← identify vulnerable code + CWE
                    └─→ supervisor.py  ← evaluate vulnerability analysis
                          └─→ patch_generation_agent.py  ← write the fix
                                └─→ patch_validation_agent.py  ← test it
                                      └─→ PATCH CONFIRMED or retry (max 3)
```

---

## Files to Build

| File | What It Does | Depends On |
|---|---|---|
| `supervisor.py` | LangGraph state machine + routing | `shared/ollama_client.py` |
| `log_analysis_agent.py` | Reconstruct attack from logs/traffic | `shared/mcp_transport.py` |
| `root_cause_agent.py` | Identify vulnerable code + CWE | `shared/memory.py` |
| `patch_generation_agent.py` | Write the patch (unified diff) | `shared/ollama_client.py` |
| `patch_validation_agent.py` | Test patch: security + functional | `shared/mcp_transport.py` |
| `state.py` | TypedDict for LangGraph state | nothing |
| `Dockerfile` | Container for this pipeline | - |

---

## Hard Rules (Enforced in Code Review)

1. **Never modify code outside the Vulnerability Analysis scope** — grounding penalty tracks this
2. **Never deploy a patch that fails functional tests** — health check required first
3. **Patch must be unified diff format** — wrapper validates before deployment
4. **Confidence < 0.6 triggers additional memory retrieval** before deployment
5. **Max 3 patch attempts per vulnerability** — supervisor enforces
6. **A patch that introduces a new vulnerability is a critical failure** — document it

---

## Dual Validation Requirement

Every patch must pass **two independent checks**:
1. **Security**: Red Team's exploit chain fails against patched container
2. **Functional**: Application still serves its intended purpose (HTTP health checks pass)

A patch that blocks an exploit by crashing the app is NOT a success.