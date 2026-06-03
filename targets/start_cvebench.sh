#!/usr/bin/env bash
# =============================================================================
# targets/start_cvebench.sh
# PURPOSE: Wrapper around CVE-Bench's ./run that adds the sandbox_targets
#          network overlay so agents can reach the target containers.
#
# USAGE:
#   ./targets/start_cvebench.sh up   CVE-2024-5084
#   ./targets/start_cvebench.sh down CVE-2024-5084
#   ./targets/start_cvebench.sh pull CVE-2024-22120 CVE-2024-5084 CVE-2024-4701 CVE-2024-36412 CVE-2024-34070
#
# PREREQUISITES:
#   - Docker running
#   - sandbox_targets network exists:  docker network create sandbox_targets
#   - CVE-Bench images pulled:          ./targets/start_cvebench.sh pull <CVE>
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVEBENCH_DIR="$SCRIPT_DIR/cvebench"
NETWORK_OVERLAY="$SCRIPT_DIR/docker-compose.cvebench-network.yml"

command="$1"
cve="$2"

if [[ -z "$command" ]]; then
    echo "Usage: $0 up|down|pull <CVE-ID> [CVE-ID...]"
    exit 1
fi

# Ensure sandbox_targets network exists
if [[ "$command" != "pull" ]]; then
    if ! docker network inspect sandbox_targets &>/dev/null; then
        echo "[cvebench] Creating sandbox_targets network..."
        docker network create sandbox_targets
    fi
fi

# Run from inside the CVE-Bench directory (./run expects to be cwd)
cd "$CVEBENCH_DIR"

if [[ "$command" == "pull" ]]; then
    shift
    ./run pull "$@"
elif [[ "$command" == "up" ]]; then
    # Set the compose file to include the network overlay
    export CVEBENCH_SANDBOX_COMPOSE_FILE="$NETWORK_OVERLAY"
    ./run up "$cve" --no-build
    echo ""
    echo "[cvebench] $cve is up."
    echo "  App:       http://localhost:9090"
    echo "  Evaluator: http://localhost:9091/status"
    echo "  Network:   sandbox_targets (agents can reach 'target' hostname)"
elif [[ "$command" == "down" ]]; then
    ./run down "$cve"
    echo "[cvebench] $cve stopped and volumes cleaned."
else
    echo "Unknown command: $command"
    echo "Usage: $0 up|down|pull <CVE-ID>"
    exit 1
fi
