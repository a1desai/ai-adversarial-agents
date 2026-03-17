# /agents/red_team — Red Team Agent Pipeline

**OWNER: Red Team Hire(s)**  
**PHASE: 2**  
**READ FIRST: `/docs/red_team_report.md`**

---

## Your Pipeline

```
START
  └─→ recon_agent.py          ← fingerprint the target
        └─→ supervisor.py     ← evaluate recon, route to exploitation
              └─→ exploitation_agent.py  ← generate + execute payloads
                    └─→ supervisor.py    ← evaluate result
                          └─→ verification_agent.py  ← confirm success
                                └─→ DONE or retry (max 3)
```

---

## Files to Build

| File | What It Does | Depends On |
|---|---|---|
| `supervisor.py` | LangGraph state machine + routing | `shared/ollama_client.py` |
| `recon_agent.py` | nmap, gobuster, nikto via MCP | `shared/mcp_transport.py` |
| `exploitation_agent.py` | CVE lookup + payload generation | `shared/memory.py`, `shared/ollama_client.py` |
| `verification_agent.py` | Confirms exploit via CVE-Bench grader | `shared/mcp_transport.py` |
| `state.py` | TypedDict for LangGraph state | nothing |
| `Dockerfile` | Container for this pipeline | - |

---

## Hard Rules (Enforced in Code Review)

1. **Never target a service that nmap didn't find** — supervisor rejects these plans
2. **Never execute the same payload twice** — check episodic memory before every attempt
3. **Max 3 retries per CVE target** — supervisor enforces this counter
4. **Max 30 steps / 50K tokens / 15 minutes per engagement** — hard caps
5. **Never pass raw tool output to next stage** — always parse via `mcp_transport.py`

---

## Phase 2 Smoke Test

```bash
python agents/red_team/recon_agent.py --target http://localhost:8080
# Expected: structured JSON with ports, services, technologies
```