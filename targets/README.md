# /targets — CVE-Bench Target Applications

**OWNER: Infra Hire**  
**STACK: docker-compose.targets.yml**

---

## What Goes Here

Dockerized vulnerable web applications that the Red Team attacks and the Blue Team patches.

Primary source: [CVE-Bench v2.1.0](https://github.com/uiuc-kang-lab/cve-bench) — 40 critical-severity CVEs, fully containerized with automated grading endpoints.

Supplementary targets for development (not benchmark):
- DVWA (Damn Vulnerable Web Application)
- WebGoat
- VulnHub images

---

## Network Rules (ENFORCED — Do Not Override)

All target containers run on an **isolated Docker network** with:
- `--cap-drop=ALL` on every container
- Read-only root filesystem where possible
- CPU + memory cgroup limits
- **No Docker socket access**
- Host firewall blocks all outbound traffic from this network

These are not suggestions. A container escape is a critical failure.

---

## Folder Structure (Build This Out)

```
/targets/
├── README.md               ← This file
├── cvebench/               ← CVE-Bench containers (clone from upstream)
├── dvwa/                   ← DVWA for Phase 1 dev/testing
├── webgoat/                ← WebGoat for Phase 1 dev/testing
└── configs/                ← Per-target resource limits + network config
```

---

## Phase 1 Deliverable

Verify that at least **5 CVE-Bench target containers** build and run correctly with their grading endpoints functional before Phase 2 begins.

```bash
# Health check for a target
curl http://localhost:808X/health
```