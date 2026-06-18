# =============================================================================
# agents/red_team/recon_agent.py
# OWNER: Red Team Hire
# PURPOSE: Reconnaissance Agent — network scanning and service fingerprinting.
#          Runs nmap, whatweb, gobuster via MCP. Returns structured JSON only.
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
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from agents.shared.mcp_transport import RedTeamTransport, ToolResult
from agents.shared.ollama_client import ModelRole, TaskType, get_client

_PROMPT_PATH = Path(__file__).parent.parent.parent / "prompts" / "red_team" / "recon_agent_v1.md"

# Common wordlist paths tried in order — first found is used
_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/opt/homebrew/share/dirb/wordlists/common.txt",
]


def _find_wordlist() -> str | None:
    for path in _WORDLISTS:
        if Path(path).exists():
            return path
    return None


class ReconAgent:
    """
    Reconnaissance Agent for the Red Team pipeline.

    Runs nmap, whatweb, and gobuster via MCP transport, then uses
    Llama 3.1 8B to synthesize raw output into structured recon JSON.
    """

    def __init__(self):
        self.transport = RedTeamTransport()
        self.llm = get_client()

    def run(self, target_url: str) -> dict:
        """
        Performs full reconnaissance on target_url.

        Steps:
            1. nmap    — port scan + service version detection
            2. whatweb — technology fingerprinting
            3. gobuster — directory enumeration
            4. LLM synthesis — raw output -> structured JSON
            5. Schema validation

        Args:
            target_url: e.g. "http://localhost:8080"

        Returns:
            Structured recon dict matching the OUTPUT FORMAT above.
        """
        logger.info(f"[recon] Starting reconnaissance on {target_url}")

        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Step 1: nmap — scan the specific port the app is listening on
        nmap_result = self.transport.run_tool(
            "nmap",
            ["-sV", "--open", "-T4", "-p", str(port), "--script", "http-headers,http-title"],
            host,
        )
        nmap_result.structured = self.transport._parse_nmap(nmap_result.raw_output)
        if not nmap_result.success:
            logger.warning(f"[recon] nmap failed: {nmap_result.error}")

        # Step 2: technology fingerprinting
        whatweb_result = self.transport.run_tool("whatweb", ["-a", "3", "--no-errors"], target_url)
        if not whatweb_result.success:
            logger.warning(f"[recon] whatweb failed: {whatweb_result.error}")

        # Step 3: directory enumeration
        # gobuster takes -u as a flag; we pass target_url as the value after -u
        wordlist = _find_wordlist()
        if wordlist:
            dir_result = self.transport.run_tool(
                "gobuster",
                ["dir", "-q", "--no-error", "-w", wordlist, "-u"],
                target_url,
            )
            if not dir_result.success:
                logger.warning(f"[recon] Directory enumeration failed: {dir_result.error}")
        else:
            logger.warning("[recon] No wordlist found on host — skipping directory enumeration")
            dir_result = ToolResult(
                tool="gobuster",
                success=False,
                raw_output="",
                truncated=False,
                token_estimate=0,
                error="No wordlist found on host",
            )

        # Step 4: LLM synthesis
        output = self._synthesize(target_url, nmap_result, whatweb_result, dir_result)

        # Step 5: validate schema — warn on low confidence but always return
        self._validate_output(output)
        if output.get("confidence", 1.0) < 0.3:
            logger.warning(
                f"[recon] Low confidence ({output['confidence']}) — tool failures likely"
            )

        logger.info(
            f"[recon] Complete: {len(output['ports'])} ports, "
            f"{len(output['technologies'])} technologies, "
            f"{len(output['potential_entry_points'])} entry points. "
            f"Confidence: {output['confidence']}"
        )
        return output

    def _synthesize(
        self,
        target_url: str,
        nmap_result: ToolResult,
        whatweb_result: ToolResult,
        dir_result: ToolResult,
    ) -> dict:
        """Builds the LLM prompt from tool outputs and parses the JSON response."""
        system_prompt = _PROMPT_PATH.read_text()

        sections = []
        if nmap_result.raw_output:
            sections.append(f"=== NMAP ===\n{nmap_result.raw_output}")
        if whatweb_result.raw_output:
            sections.append(f"=== WHATWEB ===\n{whatweb_result.raw_output}")
        if dir_result.raw_output:
            sections.append(f"=== DIRECTORIES ===\n{dir_result.raw_output}")

        tool_output = (
            "\n\n".join(sections) if sections else "(all tools failed — set confidence to 0.0)"
        )

        user_msg = f"Target: {target_url}\n\n{tool_output}\n\nReturn ONLY the JSON object."

        response_text, usage = self.llm.chat(
            role=ModelRole.REASONING,
            task=TaskType.RECON_ANALYSIS,
            messages=[{"role": "user", "content": user_msg}],
            system_prompt=system_prompt,
        )
        logger.debug(f"[recon] LLM used {usage.total} tokens")
        return self._parse_json_response(response_text)

    def _parse_json_response(self, text: str) -> dict:
        """Extracts JSON from LLM response, stripping markdown fences if present."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            end = next(
                (i for i in range(len(lines) - 1, 0, -1) if lines[i].strip() == "```"),
                len(lines),
            )
            text = "\n".join(lines[1:end])

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.error(f"[recon] LLM returned non-JSON response: {text[:300]}")
            return {
                "ports": [],
                "technologies": [],
                "directories": [],
                "potential_entry_points": [],
                "confidence": 0.0,
            }

    def _validate_output(self, output: dict) -> bool:
        """
        Validates that the recon output matches the required schema.
        Returns True if valid, raises ValueError if not.
        """
        required_keys = [
            "ports",
            "technologies",
            "directories",
            "potential_entry_points",
            "confidence",
        ]
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
