# =============================================================================
# agents/blue_team/patch_validation_agent.py
# OWNER: Blue Team Hire — SECURITY CRITICAL (lead + 1 reviewer)
# PURPOSE: Patch Validation Agent — independently tests every patch before
#          confirming success. Applies patch → functional test → security test.
# =============================================================================
#
# DUAL VALIDATION (both must pass — a crash that blocks an exploit is NOT a fix):
#   1. Functional test  → application still serves its intended purpose
#   2. Security test    → Red Team's original exploit chain fails on patched app
#
# OUTPUT FORMAT:
# {
#   "patch_applies_cleanly":    true/false,
#   "functional_tests_passed":  true/false,
#   "exploit_blocked":          true/false,
#   "regression_introduced":    true/false,   # patch broke something else
#   "details":                  "..."
# }
#
# REFERENCE: Blue Team Report — Section 4.2.5, 6.1, 6.3
# =============================================================================

import json
import shlex
from pathlib import Path

from loguru import logger

from agents.shared.mcp_transport import BLUE_TEAM_ALLOWED_TOOLS, BlueTeamTransport
from agents.shared.ollama_client import ModelRole, TaskType, get_client
from evaluation.trace_logger import load_trace

_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "prompts" / "blue_team" / "patch_validation_agent_v1.md"
)

_HEALTH_CHECK_ARGS = ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10"]
_RESULT_KEYS = [
    "exploit_blocked",
    "regression_introduced",
    "details",
]


class PatchValidationAgent:
    """
    Patch Validation Agent for the Blue Team pipeline.

    Applies the proposed patch to a fresh copy of the target container,
    runs functional health checks, then replays the Red Team's exploit chain
    to confirm the vulnerability is neutralized.
    """

    def __init__(self):
        self.transport = BlueTeamTransport()
        self.llm = get_client()

    def validate(
        self,
        container_id: str,
        patch_diff: str,
        allowed_patch_paths: list[str],
        functional_health_url: str,
        exploit_replay_trace: str,
    ) -> dict:
        """
        Runs the three-stage validation protocol.

        Args:
            container_id:          fresh copy of the target container
            patch_diff:            unified diff from PatchGenerationAgent
            allowed_patch_paths:   from RootCauseAgent.allowed_patch_paths
                                   (mcp_transport will enforce this whitelist)
            functional_health_url: e.g. http://target:80/health
            exploit_replay_trace:  trace ID of the original Red Team exploit

        Returns:
            Validation dict matching the OUTPUT FORMAT above.
        """
        logger.info(f"[patch_validation] Validating patch on {container_id}")

        # Step 1: apply patch — scope violations return immediately, no further steps
        deploy_result = self.transport.deploy_patch(container_id, patch_diff, allowed_patch_paths)
        if not deploy_result.success:
            logger.error(f"[patch_validation] Patch did not apply cleanly: {deploy_result.error}")
            return self._result(
                patch_applies_cleanly=False,
                functional_tests_passed=False,
                exploit_blocked=False,
                regression_introduced=False,
                details=deploy_result.error or "Patch did not apply cleanly",
            )

        # Step 2: functional health check
        functional_ok, health_details = self._check_functional_health(functional_health_url)

        # Step 3: replay the original exploit against the patched container
        exploit_blocked, regression_introduced, replay_details = self._replay_exploit(
            exploit_replay_trace, functional_ok
        )

        result = self._result(
            patch_applies_cleanly=True,
            functional_tests_passed=functional_ok,
            exploit_blocked=exploit_blocked,
            regression_introduced=regression_introduced,
            details=f"{health_details} | {replay_details}",
        )
        logger.info(
            f"[patch_validation] functional={functional_ok} exploit_blocked={exploit_blocked} "
            f"regression={regression_introduced}"
        )
        return result

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _result(
        self,
        patch_applies_cleanly: bool,
        functional_tests_passed: bool,
        exploit_blocked: bool,
        regression_introduced: bool,
        details: str,
    ) -> dict:
        return {
            "patch_applies_cleanly": patch_applies_cleanly,
            "functional_tests_passed": functional_tests_passed,
            "exploit_blocked": exploit_blocked,
            "regression_introduced": regression_introduced,
            "details": details,
        }

    def _check_functional_health(self, functional_health_url: str) -> tuple[bool, str]:
        """Curls the health endpoint; 2xx/3xx counts as healthy."""
        result = self.transport.run_tool("curl", _HEALTH_CHECK_ARGS, functional_health_url)
        status = result.raw_output.strip()
        healthy = result.success and status.isdigit() and 200 <= int(status) < 400
        return healthy, f"Health check {functional_health_url} -> HTTP {status or 'no response'}"

    def _replay_exploit(self, trace_id: str, functional_ok: bool) -> tuple[bool, bool, str]:
        """
        Replays the original Red Team payload (from the engagement trace) against
        the now-patched container. If none of the original success indicators
        appear anymore, the deterministic check treats the exploit as blocked;
        genuinely ambiguous evidence is handed to the LLM rubric instead of guessed.
        """
        try:
            events = load_trace(trace_id)
        except FileNotFoundError:
            logger.warning(f"[patch_validation] No trace found for '{trace_id}' — cannot replay")
            return (
                False,
                False,
                f"No trace available for '{trace_id}' — exploit not confirmed blocked",
            )

        exploit_event = next(
            (
                e
                for e in reversed(events)
                if e.agent == "exploitation_agent" and e.action == "execute_payload"
            ),
            None,
        )
        if exploit_event is None:
            logger.warning(f"[patch_validation] Trace '{trace_id}' has no execute_payload event")
            return False, False, "Trace has no execute_payload event to replay"

        payload_used = exploit_event.output.get("payload_used", "")
        success_indicators = exploit_event.output.get("success_indicators", [])
        try:
            tokens = shlex.split(payload_used) if payload_used else []
        except ValueError as exc:
            # Real exploit payloads (e.g. "1' OR 1=1--") routinely contain unbalanced
            # quotes that shlex can't tokenize — degrade gracefully, don't crash validation.
            logger.warning(
                f"[patch_validation] Payload not shlex-parseable ({exc}): {payload_used!r}"
            )
            return False, False, "Could not parse the original payload for replay"
        if len(tokens) < 2:
            logger.warning(
                f"[patch_validation] Could not parse payload for replay: {payload_used!r}"
            )
            return False, False, "Could not parse the original payload for replay"

        tool, target = tokens[0], tokens[-1]
        args = tokens[1:-1]
        if tool not in BLUE_TEAM_ALLOWED_TOOLS:
            logger.warning(
                f"[patch_validation] Original tool '{tool}' not replayable by Blue Team "
                "— falling back to a plain curl of the same endpoint"
            )
            replay_result = self.transport.run_tool("curl", ["-s", "-L"], target)
        else:
            replay_result = self.transport.run_tool(tool, args, target)

        response = replay_result.raw_output
        matched = [ind for ind in success_indicators if ind and ind.lower() in response.lower()]

        if matched:
            # Deterministic: the original exploit still works. No LLM needed.
            return False, False, f"Replay still matched success indicators: {matched}"

        # No success indicators matched — ambiguous whether this is a graceful
        # rejection (exploit_blocked) or a crash (regression). Defer to the rubric.
        return self._interpret_replay_with_llm(success_indicators, response, functional_ok)

    def _interpret_replay_with_llm(
        self,
        success_indicators: list[str],
        replayed_response: str,
        functional_ok: bool,
    ) -> tuple[bool, bool, str]:
        """Uses the REASONING model to interpret ambiguous exploit-replay evidence."""
        system_prompt = _PROMPT_PATH.read_text()
        user_msg = (
            f"## Original Success Indicators\n{success_indicators}\n\n"
            f"## Replayed Response\n{replayed_response}\n\n"
            f"## Functional Health Check Passed\n{functional_ok}\n\n"
            "Return ONLY the JSON validation interpretation."
        )

        response_text, usage = self.llm.chat(
            role=ModelRole.REASONING,
            task=TaskType.VULNERABILITY_ANALYSIS,
            messages=[{"role": "user", "content": user_msg}],
            system_prompt=system_prompt,
        )
        logger.debug(f"[patch_validation] LLM used {usage.total} tokens")
        parsed = self._parse_json_response(response_text)
        return (
            parsed["exploit_blocked"],
            parsed["regression_introduced"],
            parsed["details"],
        )

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
            logger.error(f"[patch_validation] LLM returned non-JSON: {text[:300]}")
            return self._unconfirmed_result()

        for key in _RESULT_KEYS:
            if key not in parsed:
                logger.error(f"[patch_validation] LLM result missing key '{key}'")
                return self._unconfirmed_result()

        return parsed

    def _unconfirmed_result(self) -> dict:
        """Conservative fallback — never claim blocked without confirmation."""
        return {
            "exploit_blocked": False,
            "regression_introduced": False,
            "details": "LLM interpretation could not be parsed — exploit not confirmed blocked",
        }
