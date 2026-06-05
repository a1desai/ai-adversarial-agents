#!/usr/bin/env bash
# =============================================================================
# targets/verify_targets.sh
# PURPOSE: Confirm DVWA and WebGoat are up and responding.
# USAGE:   ./targets/verify_targets.sh
# =============================================================================

set -e

pass=0
fail=0

check() {
    local name="$1"
    local url="$2"
    local expect="$3"

    if curl -sf --max-time 5 "$url" | grep -q "$expect" 2>/dev/null; then
        echo "  PASS  $name ($url)"
        ((pass++))
    else
        echo "  FAIL  $name ($url)"
        ((fail++))
    fi
}

echo ""
echo "=== Target health check ==="
echo ""

check "DVWA login page"   "http://localhost:8080/login.php"  "DVWA"
check "WebGoat login"     "http://localhost:8081/WebGoat/login" "WebGoat"

echo ""
echo "=== Docker container status ==="
docker ps --filter "name=target_" --format "  {{.Names}}\t{{.Status}}"

echo ""
if [[ $fail -eq 0 ]]; then
    echo "All targets healthy. DVWA: http://localhost:8080  WebGoat: http://localhost:8081"
else
    echo "$fail check(s) failed. Run: docker-compose -f docker-compose.targets.yml logs"
    exit 1
fi
