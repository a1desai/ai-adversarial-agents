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

import json
from pathlib import Path

from loguru import logger

from agents.shared.mcp_transport import BlueTeamTransport
from agents.shared.ollama_client import ModelRole, TaskType, get_client
from hypervisor.packet_logger import PacketRecord, load_packets

_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "prompts" / "blue_team" / "log_analysis_agent_v1.md"
)

# CVE-Bench standard attack goals — must match verification_agent.CVE_BENCH_ATTACK_GOALS.
# Duplicated (not imported) so Blue Team code never depends on agents/red_team/.
CVE_BENCH_ATTACK_GOALS = {
    "denial_of_service",
    "unauthorized_login",
    "privilege_escalation",
    "database_access",
    "database_modification",
    "file_access",
    "file_creation",
    "remote_code_execution",
}

_SUMMARY_KEYS = [
    "target_endpoint",
    "payload_observed",
    "attack_goal_achieved",
    "http_status_sequence",
    "evidence_excerpts",
    "confidence",
]

_LOW_CONFIDENCE_THRESHOLD = 0.3
_MAX_PACKET_RECORDS_IN_CONTEXT = 50


class LogAnalysisAgent:
    """
    Log Analysis Agent for the Blue Team pipeline.

    Reads container logs and packet captures via MCP. Uses Llama 3.1 8B
    to reconstruct the attack chain into a structured Attack Summary.
    """

    def __init__(self):
        self.transport = BlueTeamTransport()
        self.llm = get_client()

    def analyze(
        self,
        container_id: str,
        exploit_timestamp: str,
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
        logger.info(
            f"[log_analysis] Reconstructing attack container={container_id} "
            f"exploit_timestamp={exploit_timestamp}"
        )

        # Step 1: read logs via MCP transport (already truncated inside read_logs)
        log_result = self.transport.read_logs(container_id, since_seconds=time_window_seconds)

        # Step 2 + 3: LLM analysis, parsed into the Attack Summary schema
        summary = self._analyze_with_llm(log_result.raw_output, exploit_timestamp)

        # Step 5: low confidence escalates to a packet-capture supplement
        if summary.get("confidence", 1.0) < _LOW_CONFIDENCE_THRESHOLD:
            logger.warning(
                f"[log_analysis] Low confidence ({summary.get('confidence')}) — "
                "escalating to packet capture supplement"
            )
            summary = self._escalate_with_packet_capture(
                container_id, log_result.raw_output, exploit_timestamp, summary
            )

        # Step 4: validate schema before returning
        self._validate_output(summary)

        if summary["attack_goal_achieved"] not in CVE_BENCH_ATTACK_GOALS:
            logger.warning(
                f"[log_analysis] attack_goal_achieved '{summary['attack_goal_achieved']}' "
                f"not in CVE-Bench goal set — leaving as-is for root cause analysis to see"
            )

        logger.info(
            f"[log_analysis] Summary: endpoint={summary.get('target_endpoint')} "
            f"goal={summary.get('attack_goal_achieved')} confidence={summary.get('confidence')}"
        )
        return summary

    def _validate_output(self, output: dict) -> bool:
        """
        Validates that the attack summary matches the required schema.
        Returns True if valid, raises ValueError if not.
        """
        for key in _SUMMARY_KEYS:
            if key not in output:
                raise ValueError(f"Attack summary missing required key: '{key}'")
        return True

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _analyze_with_llm(self, logs: str, exploit_timestamp: str) -> dict:
        """Assembles context from the raw logs and calls the log-analysis LLM."""
        system_prompt = _PROMPT_PATH.read_text()
        user_msg = (
            f"## Exploit Timestamp\n{exploit_timestamp}\n\n"
            f"## Container Logs\n{logs}\n\n"
            "Return ONLY the JSON attack summary."
        )

        response_text, usage = self.llm.chat(
            role=ModelRole.REASONING,
            task=TaskType.LOG_ANALYSIS,
            messages=[{"role": "user", "content": user_msg}],
            system_prompt=system_prompt,
        )
        logger.debug(f"[log_analysis] LLM used {usage.total} tokens")
        return self._parse_json_response(response_text)

    def _escalate_with_packet_capture(
        self,
        container_id: str,
        logs: str,
        exploit_timestamp: str,
        low_confidence_summary: dict,
    ) -> dict:
        """Re-runs analysis with a packet-capture supplement, if one is available."""
        try:
            packets = load_packets(container_id)
        except FileNotFoundError:
            logger.warning(
                f"[log_analysis] No packet capture available for {container_id} — "
                "keeping low-confidence log-only result"
            )
            return low_confidence_summary

        packet_summary = self._summarize_packets(packets)
        system_prompt = _PROMPT_PATH.read_text()
        user_msg = (
            f"## Exploit Timestamp\n{exploit_timestamp}\n\n"
            f"## Container Logs\n{logs}\n\n"
            f"## Packet Capture Supplement\n{packet_summary}\n\n"
            "Return ONLY the JSON attack summary."
        )

        response_text, usage = self.llm.chat(
            role=ModelRole.REASONING,
            task=TaskType.LOG_ANALYSIS,
            messages=[{"role": "user", "content": user_msg}],
            system_prompt=system_prompt,
        )
        logger.debug(f"[log_analysis] Packet-supplemented LLM used {usage.total} tokens")
        return self._parse_json_response(response_text)

    def _summarize_packets(self, packets: list[PacketRecord]) -> str:
        """Renders a compact, human-readable summary of captured packets."""
        lines = []
        for record in packets[:_MAX_PACKET_RECORDS_IN_CONTEXT]:
            lines.append(
                f"[{record.seq}] {record.direction} {record.src} -> {record.dst} "
                f"({record.length} bytes)"
            )
        if len(packets) > _MAX_PACKET_RECORDS_IN_CONTEXT:
            lines.append(f"... ({len(packets) - _MAX_PACKET_RECORDS_IN_CONTEXT} more records)")
        return "\n".join(lines) if lines else "No packets captured for this engagement."

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
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.error(f"[log_analysis] LLM returned non-JSON: {text[:300]}")
            return self._empty_summary()

        for key in _SUMMARY_KEYS:
            if key not in parsed:
                logger.error(f"[log_analysis] LLM summary missing key '{key}' — using default")
                return self._empty_summary()

        return parsed

    def _empty_summary(self) -> dict:
        """Zero-confidence fallback when the LLM response can't be used."""
        return {
            "target_endpoint": "",
            "payload_observed": "",
            "attack_goal_achieved": "",
            "http_status_sequence": [],
            "evidence_excerpts": [],
            "confidence": 0.0,
        }
