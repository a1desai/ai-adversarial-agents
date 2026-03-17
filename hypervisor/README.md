# /hypervisor — Sandbox Hypervisor

**OWNER: Infra Hire**  
**STACK: docker-compose.hypervisor.yml**

---

## What Goes Here

The network bridge between the agent infrastructure (Stack 2) and the target applications (Stack 1). Every packet between agents and targets flows through here.

---

## Responsibilities

1. **Network Bridge** — Routes traffic between `agents` network and `targets` network
2. **Packet Logging** — Captures all traffic for Blue Team evidence reconstruction
3. **Exploit Detection** — Relays CVE-Bench grader results to Blue Team Supervisor
4. **Resource Enforcement** — Enforces CPU/memory limits per container

---

## Critical: Red–Blue Coordination Events

The hypervisor emits events that the Blue Team Supervisor listens to:

```
EVENT: exploit_detected
PAYLOAD: {
    "cve_id": "CVE-XXXX-XXXX",
    "target_endpoint": "/vulnerable/path",
    "attack_goal_achieved": "remote_code_execution",
    "timestamp": "ISO-8601"
}
```

The Blue Team **only activates on confirmed exploit detection** — not on a timer.

---

## Folder Structure (Build This Out)

```
/hypervisor/
├── README.md               ← This file
├── bridge.py               ← Network bridge logic
├── packet_logger.py        ← Full packet capture for Blue Team evidence
├── event_emitter.py        ← Exploit detection events → Blue Team
└── firewall_rules.sh       ← Host firewall configuration
```

---

## Security Review Required

All files in this folder require **lead + one additional hire** sign-off before merge.