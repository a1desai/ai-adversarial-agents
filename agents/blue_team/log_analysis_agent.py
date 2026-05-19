# =============================================================================
# agents/blue_team/log_analysis_agent.py
# OWNER: Blue Team Hire
# PURPOSE: Log Analysis Agent — monitors system logs and reconstructs the
#          attack chain from observable evidence (logs + packet captures).
# =============================================================================
#
# SCOPE: This agent only sees logs and network captures. It NEVER sees source
#        code. It NEVER sees the Red Team's internal reasoning or prompts.
#        It reconstructs the attack purely from externally observable evidence.
#
# OUTPUT FORMAT (required — supervisor validates this schema):
# {
#   "target_endpoint":      "/vulnerable/path",
#   "payload_observed":     "...",                     # truncated
#   "attack_goal_achieved": "remote_code_execution",   # one of CVE-Bench goals
#   "http_status_sequence": [200, 500, 200],
#   "evidence_excerpts":    ["..."],                   # supporting log lines
#   "confidence":           0.0-1.0
# }
#
# REFERENCE: Blue Team Report — Section 4.2.2, 4.5
# =============================================================================

from loguru import logger

from agents.shared.mcp_transport import BlueTeamTransport
from agents.shared.ollama_client import get_client, ModelRole, TaskType


class LogAnalysisAgent:
    """
    Log Analysis Agent for the Blue Team pipeline.

    Reads container logs and packet captures via MCP. Uses Llama 3.1 8B
    to reconstruct the attack chain into a structured Attack Summary.
    """

    def __init__(self):
        self.transport = BlueTeamTransport()
        self.llm       = get_client()

    def analyze(
        self,
        container_id:        str,
        exploit_timestamp:   str,
        time_window_seconds: int = 300,
    ) -> dict:
        """
        Reconstructs the attack chain from logs around the exploit timestamp.

        Args:
            container_id:        target container the Red Team exploited
            exploit_timestamp:   when the grader confirmed success (ISO 8601)
            time_window_seconds: how far back to search (default: 5 minutes)

        Returns:
            Attack Summary dict matching the OUTPUT FORMAT above.
        """
        # TODO (Blue Team Hire):
        # Step 1: read logs via self.transport.read_logs(container_id, since_seconds=...)
        # Step 2: pass truncated logs to Llama 3.1 8B with LOG_ANALYSIS task
        # Step 3: parse LLM output into Attack Summary JSON
        # Step 4: validate schema before returning
        # Step 5: if confidence < 0.3 → log warning, escalate to packet capture supplement

        raise NotImplementedError("LogAnalysisAgent.analyze() not yet implemented")

    def _validate_output(self, output: dict) -> bool:
        """
        Validates that the attack summary matches the required schema.
        Returns True if valid, raises ValueError if not.
        """
        required_keys = [
            "target_endpoint",
            "payload_observed",
            "attack_goal_achieved",
            "http_status_sequence",
            "evidence_excerpts",
            "confidence",
        ]
        for key in required_keys:
            if key not in output:
                raise ValueError(f"Attack summary missing required key: '{key}'")
        return True
