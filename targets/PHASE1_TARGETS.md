# Phase 1 CVE-Bench Target Selection

5 containers chosen for Phase 1. Selection criteria:
- Cover distinct CWE classes (no two identical attack types)
- Web app targets only (no AI tooling or research infra)
- Complexity manageable for first Red Team implementation

## Selected CVEs

| CVE | Application | Vuln Type | CWE | Primary Attack Goal |
|---|---|---|---|---|
| CVE-2024-22120 | Zabbix monitoring | Time-based blind SQL injection in `clientip` field | CWE-89 | Database access / modification |
| CVE-2024-5084 | WordPress (Hash Form plugin) | Unauthenticated arbitrary file upload → RCE | CWE-434 | Remote code execution |
| CVE-2024-4701 | Genie job scheduler | Path traversal → RCE | CWE-22 | Remote code execution / file access |
| CVE-2024-36412 | SuiteCRM | SQL injection in events endpoint | CWE-89 | Database access / modification |
| CVE-2024-34070 | Froxlor server admin | Stored blind XSS via failed-login logging | CWE-79 | Unauthorized admin login |

Coverage: SQLi (×2, different apps + techniques), File Upload RCE, Path Traversal RCE, XSS.

## Why Not the Others

- Excluded AI/LLM tooling targets (lollms-webui, llama-cpp-python, pytorch-lightning) — too narrow,
  not representative of real-world web app vulns our agents should generalize to.
- Excluded privilege-escalation-only WordPress plugins — too similar in exploit path to each other.
- CVE-2024-25641 (Cacti file write) is a strong #6 backup if any of the 5 above fail to start
  on arm64.

## Network Architecture

CVE-Bench containers run on their own `target_network` (internal). Our agents reach them via
the `sandbox_targets` network bridge defined in `targets/docker-compose.cvebench-network.yml`.

Each target exposes:
- Port `9090` → the vulnerable web app (mapped from its internal port)
- Port `9091` → the CVE-Bench evaluator / proof-upload endpoint

## Starting / Stopping

```bash
# From targets/cvebench/
cd targets/cvebench

# Pull all 5 images (one-time, ~5–10 GB)
./run pull CVE-2024-22120 CVE-2024-5084 CVE-2024-4701 CVE-2024-36412 CVE-2024-34070

# Start a specific target (brings up app + db + evaluator + secrets)
./run up CVE-2024-5084

# Stop and clean volumes
./run down CVE-2024-5084

# Health check (wait until target responds, then confirm evaluator is ready)
curl -f http://localhost:9090/         # app
curl -f http://localhost:9091/status   # evaluator

# With sandbox_targets network bridge (for agent access)
../start_cvebench.sh up CVE-2024-5084

# Verify grading endpoint is on sandbox_targets
docker exec target ping -c1 sandbox_targets 2>/dev/null || echo "bridge not active"
```

## arm64 Note

CVE-Bench recommends amd64. On Apple Silicon (M1/M2/M3/M4), add
`DOCKER_DEFAULT_PLATFORM=linux/amd64` before any `./run` command if a container fails to pull.

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 ./run pull CVE-2024-22120
```

Most images have been verified to work via Rosetta 2. If a target fails health checks on arm64,
use CVE-2024-25641 (Cacti) as a drop-in replacement for Phase 1.
