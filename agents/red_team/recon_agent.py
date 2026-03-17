# =============================================================================
# agents/red_team/recon_agent.py
# OWNER: Red Team Hire
# PURPOSE: Reconnaissance Agent — network scanning and service fingerprinting.
#          Runs nmap, gobuster, nikto via MCP. Returns structured JSON only.
# =============================================================================
#
# SCOPE: This agent only sees target URLs and returns structured recon JSON.
#        It NEVER sees exploit payloads. It NEVER writes to memory directly.
#
# OUTPUT FORMAT (required — supervisor validates this schema):
# {
#   "ports": [{"port": "80/tcp", "state": "open", "service": "http", "version": "..."}],
#   "technologies": ["WordPress 6.4", "PHP 8.1", "Apache 2.4"],
#   "directories": ["/admin", "/wp-login.php"],
#   "potential_entry_points": ["/wp-admin/admin-ajax.php"],
#   "confidence": 0.0-1.0
# }
#
# REFERENCE: Red Team Report — Section 4.2.2
# =============================================================================

import argparse
import json
from loguru import logger

from agents.shared.mcp_transport import RedTeamTransport
from agents.shared.ollama_client import get_client, ModelRole, TaskType


class ReconAgent:
    """
    Reconnaissance Agent for the Red Team pipeline.

    Runs network scanning tools via MCP and uses Llama 3.1 8B
    to parse raw output into structured reconnaissance data.
    """

    def __init__(self):
        self.transport = RedTeamTransport()
        self.llm       = get_client()

    def run(self, target_url: str) -> dict:
        """
        Performs full reconnaissance on target_url.

        Steps:
            1. nmap — port scan + service version detection
            2. whatweb — technology fingerprinting
            3. gobuster/feroxbuster — directory enumeration
            4. LLM parsing — raw output → structured JSON

        Args:
            target_url: e.g. "http://localhost:8080"

        Returns:
            Structured recon dict matching the OUTPUT FORMAT above.
        """
        logger.info(f"[recon] Starting reconnaissance on {target_url}")

        # Step 1: nmap scan
        # TODO (Red Team Hire): run nmap via self.transport.nmap_scan()
        # and extract ports/services from result.structured

        # Step 2: technology fingerprinting
        # TODO: run whatweb via self.transport.run_tool("whatweb", [...], target_url)

        # Step 3: directory enumeration
        # TODO: run gobuster or feroxbuster
        # NOTE: truncation is enforced in mcp_transport — don't add your own

        # Step 4: LLM synthesis
        # TODO: pass truncated tool outputs to Llama 3.1 8B with RECON_ANALYSIS task
        # Ask it to produce the structured JSON format defined above
        # Use: self.llm.chat(role=ModelRole.REASONING, task=TaskType.RECON_ANALYSIS, ...)

        # Step 5: Validate output schema before returning
        # TODO: validate that all required keys are present
        # If confidence < 0.3, log a warning but still return

        raise NotImplementedError("ReconAgent.run() not yet implemented")

    def _validate_output(self, output: dict) -> bool:
        """
        Validates that the recon output matches the required schema.
        Returns True if valid, raises ValueError if not.
        """
        required_keys = ["ports", "technologies", "directories", "potential_entry_points", "confidence"]
        for key in required_keys:
            if key not in output:
                raise ValueError(f"Recon output missing required key: '{key}'")
        return True


# ---------------------------------------------------------------------------
# CLI entry point — Phase 1 smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Red Team Recon Agent")
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://localhost:8080)")
    args = parser.parse_args()

    agent = ReconAgent()
    result = agent.run(args.target)
    print(json.dumps(result, indent=2))