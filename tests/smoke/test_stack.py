# =============================================================================
# tests/smoke/test_stack.py
# OWNER: Lead / Infra Hire
# MARKERS: smoke (requires Ollama running + Docker up)
# PURPOSE: Verifies the full stack is wired correctly end to end.
#          Run this after setting up a new machine, not during normal dev.
# RUN: pytest tests/smoke/ -m smoke -v
# =============================================================================

import json
import subprocess

import pytest

pytestmark = pytest.mark.smoke

# Tiny image used as a throwaway network-egress probe (auto-pulled on first run).
PROBE_IMAGE = "busybox:1.36"
# The vulnerable app containers that MUST run with all Linux capabilities dropped.
# target_dvwa_db is intentionally excluded — MySQL needs caps to drop privileges
# at startup, and it sits on an internal-only network (see docker-compose.targets.yml).
CAP_DROP_TARGETS = ["target_dvwa", "target_webgoat"]


def _docker_available() -> bool:
    return subprocess.run(["docker", "ps"], capture_output=True, text=True).returncode == 0


def _network_exists(name: str) -> bool:
    out = subprocess.run(
        ["docker", "network", "ls", "--filter", f"name={name}", "--format", "{{.Name}}"],
        capture_output=True,
        text=True,
    ).stdout
    return name in out.split()


def _container_running(name: str) -> bool:
    out = subprocess.run(
        ["docker", "ps", "--filter", f"name={name}", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    ).stdout
    return name in out.split()


class TestOllamaConnectivity:
    def test_ollama_is_reachable(self):
        """Ollama must be running on localhost:11434."""
        import httpx

        try:
            response = httpx.get("http://localhost:11434/api/tags", timeout=5)
            assert response.status_code == 200, "Ollama returned non-200"
        except Exception as e:
            pytest.fail(f"Ollama not reachable: {e}. Run: ollama serve")

    def test_required_models_are_pulled(self):
        """All three required models must be available in Ollama."""
        from agents.shared.ollama_client import get_client

        client = get_client()
        assert client.verify_models_available(), (
            "One or more models missing. Run:\n"
            "  ollama pull llama3.1:8b-instruct-q4_K_M\n"
            "  ollama pull qwen2.5-coder:7b-instruct-q4_K_M\n"
            "  ollama pull nomic-embed-text"
        )

    def test_ollama_returns_valid_response(self):
        """Smoke test: send a minimal prompt, expect a response."""
        from agents.shared.ollama_client import ModelRole, TaskType, get_client

        client = get_client()
        response, usage = client.chat(
            role=ModelRole.REASONING,
            task=TaskType.LOG_ANALYSIS,
            messages=[{"role": "user", "content": "Reply with only the word: OK"}],
        )
        assert len(response) > 0
        assert usage.total > 0


class TestChromaDBConnectivity:
    def test_chromadb_initializes(self):
        """ChromaDB must initialize all 6 collections without error."""
        from agents.shared.memory import ALL_COLLECTIONS, initialize_all_collections

        collections = initialize_all_collections()
        assert len(collections) == len(ALL_COLLECTIONS)

    def test_chromadb_write_and_read(self):
        """Can write a record and retrieve it."""
        from agents.shared.memory import CVE_KNOWLEDGE, get_collection

        col = get_collection(CVE_KNOWLEDGE)
        test_id = "smoke-test-cve-0001"

        # Clean up if leftover from previous run
        import contextlib

        with contextlib.suppress(Exception):
            col.delete(ids=[test_id])

        col.add(
            ids=[test_id],
            documents=["SQL injection test record for smoke testing"],
            metadatas=[{"cve_id": test_id, "cvss_score": 9.8}],
        )
        results = col.query(query_texts=["SQL injection"], n_results=1)
        assert test_id in results["ids"][0]

        # Cleanup
        col.delete(ids=[test_id])


class TestDockerConnectivity:
    def test_docker_is_running(self):
        """Docker must be accessible."""
        result = subprocess.run(["docker", "ps"], capture_output=True, text=True)
        assert result.returncode == 0, "Docker not running or not accessible"

    def test_target_network_exists(self):
        """sandbox_targets network must exist."""
        result = subprocess.run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                "name=sandbox_targets",
                "--format",
                "{{.Name}}",
            ],
            capture_output=True,
            text=True,
        )
        assert "sandbox_targets" in result.stdout, (
            "sandbox_targets network not found. Run: docker-compose up"
        )

    def test_dvwa_container_is_running(self):
        """DVWA target container must be running for Phase 1 testing."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=target_dvwa", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        assert "target_dvwa" in result.stdout, (
            "DVWA container not running. Run: docker-compose -f docker-compose.targets.yml up -d"
        )


class TestNetworkIsolation:
    """Codifies the sandbox isolation guarantees as CI-enforced checks (issue #8).

    A regression here (a target gaining internet egress, or a capability not
    being dropped) breaks the build instead of silently weakening the sandbox.
    """

    def test_sandbox_targets_has_no_internet_egress(self):
        """A container on sandbox_targets must NOT be able to reach the internet.

        We launch a throwaway probe attached ONLY to sandbox_targets and try to
        reach an external IP. The internal network has no default route, so this
        must fail. We probe the network directly rather than exec'ing into a
        target, because targets may be multi-homed onto a non-internal dev
        network for host port publishing (see PR #26 review) — the guarantee we
        enforce here is specifically that sandbox_targets itself has no egress.
        """
        if not _docker_available():
            pytest.skip("Docker not available")
        if not _network_exists("sandbox_targets"):
            pytest.skip("sandbox_targets network not created — see docker-compose.yml")

        # -T 5: 5s connect timeout. Reaching a raw IP avoids DNS masking the result.
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "sandbox_targets",
                PROBE_IMAGE,
                "sh",
                "-c",
                "wget -q -T 5 -O /dev/null http://1.1.1.1 && echo REACHED || echo BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert "BLOCKED" in result.stdout and "REACHED" not in result.stdout, (
            "sandbox_targets reached the internet — isolation is broken! "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )

    @pytest.mark.parametrize("container", CAP_DROP_TARGETS)
    def test_target_drops_all_capabilities(self, container):
        """Each vulnerable target container must run with cap_drop: ALL."""
        if not _docker_available():
            pytest.skip("Docker not available")
        if not _container_running(container):
            pytest.skip(f"{container} not running — start docker-compose.targets.yml")

        inspect = subprocess.run(
            ["docker", "inspect", container],
            capture_output=True,
            text=True,
        )
        assert inspect.returncode == 0, f"docker inspect {container} failed: {inspect.stderr}"
        cap_drop = json.loads(inspect.stdout)[0]["HostConfig"]["CapDrop"] or []
        assert "ALL" in cap_drop, (
            f"{container} does not drop ALL capabilities (CapDrop={cap_drop}). "
            "Every target must keep the security block in docker-compose.targets.yml."
        )
