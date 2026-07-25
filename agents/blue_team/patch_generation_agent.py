# =============================================================================
# agents/blue_team/patch_generation_agent.py
# OWNER: Blue Team Hire
# PURPOSE: Patch Generation Agent — cognitive core of the Blue Team.
#          Generates unified diff patches from Vulnerability Analysis output.
# =============================================================================
#
# THIS FILE IS SECURITY CRITICAL — requires lead review before merge.
# A bad patch IS a security vulnerability. A patch that introduces a new
# vulnerability is a critical failure that must be root-caused and documented.
#
# PATCH RULES (enforced by wrapper, not just prompt):
#   ✓ Patch must be valid unified diff format (wrapper validates syntax)
#   ✓ Patch must only modify files in vulnerability_analysis["allowed_patch_paths"]
#      (enforced by mcp_transport._validate_patch_scope)
#   ✓ Patch must be minimal — smallest change that fixes the vulnerability
#   ✗ Patch must NOT disable security features (e.g., turning off WAF rules)
#   ✗ Patch must NOT modify code outside the vulnerable function/file
#
# CONFIDENCE RULE:
#   If patch_confidence < 0.6, do NOT deploy.
#   Trigger additional memory retrieval and regenerate.
#
# REFERENCE: Blue Team Report — Section 4.2.4, 5.3
# =============================================================================

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from agents.shared.memory import BLUE_EPISODIC, get_collection, parallel_retrieval
from agents.shared.ollama_client import ModelRole, TaskType, get_client

_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "prompts" / "blue_team" / "patch_generation_agent_v1.md"
)

_PATCH_KEYS = ["patch_diff", "confidence", "strategy_used", "rationale"]

MINIMUM_CONFIDENCE_TO_DEPLOY = 0.6

_MANY_PRIOR_FAILURES_THRESHOLD = 2
_MAX_SOURCE_CHARS = 6_000  # defensive cap — read_source_file already truncates upstream

_STRATEGY_HINTS = {
    1: "primary procedural memory approach",
    2: "alternative CWE remediation pattern (attempt 1 failed or regressed)",
    3: "most conservative possible change (attempts 1 and 2 failed)",
}


class PatchGenerationAgent:
    """
    Patch Generation Agent for the Blue Team pipeline.

    Uses Qwen2.5-Coder for patch code generation,
    falls back to Llama 3.1 8B on constrained hardware.
    """

    def __init__(self):
        self.llm = get_client()

    def generate_patch(
        self,
        vulnerability_analysis: dict,
        source_code: str,
        attempt_number: int = 1,
    ) -> dict:
        """
        Generates a unified diff patch for the identified vulnerability.

        Args:
            vulnerability_analysis: output from RootCauseAgent — must contain
                                     cwe_classification, vulnerable_file,
                                     vulnerable_function, allowed_patch_paths
            source_code:             content of the vulnerable file (truncated)
            attempt_number:          1, 2, or 3 — used to vary strategy on retry

        Returns:
            {
                "patch_diff":    "unified diff string",
                "confidence":    0.0-1.0,
                "strategy_used": "applied PDO prepared statements",
                "rationale":     "CWE-89 in PHP requires..."
            }
        """
        cwe_classification = vulnerability_analysis.get("cwe_classification", "unknown")
        logger.info(
            f"[patch_generation] Generating patch cwe={cwe_classification} "
            f"attempt={attempt_number}"
        )

        # Step 1: parallel memory retrieval, filtered to this CWE type for blue_procedural
        cwe_type = cwe_classification.split(":", 1)[0].strip()
        metadata_filter = {"cwe_type": cwe_type} if cwe_type and cwe_type != "unknown" else None
        memory = parallel_retrieval(
            cwe_classification, team="blue", n_results_each=3, metadata_filter=metadata_filter
        )

        # Step 2: prior failed attempts for this CWE — feed reasons back to avoid repeats
        failed_prior = [
            r for r in memory["episodic"] if r.get("metadata", {}).get("outcome") == "FAILURE"
        ]
        if len(failed_prior) >= _MANY_PRIOR_FAILURES_THRESHOLD:
            logger.debug("[patch_generation] Many prior failures — expanding procedural retrieval")
            extra = parallel_retrieval(
                cwe_classification, team="blue", n_results_each=5, metadata_filter=metadata_filter
            )
            memory["procedural"] = extra["procedural"]

        # Step 3: strategy varies by attempt_number
        strategy_hint = _STRATEGY_HINTS.get(attempt_number, _STRATEGY_HINTS[3])

        # Step 4 + 5: assemble context and generate
        patch = self._generate_with_llm(
            vulnerability_analysis, source_code, memory, failed_prior, attempt_number, strategy_hint
        )

        # Step 6: validate diff format; one retry on malformed output before giving up
        if not self._validate_diff_format(patch.get("patch_diff", "")):
            logger.warning("[patch_generation] Malformed diff — retrying once")
            patch = self._generate_with_llm(
                vulnerability_analysis,
                source_code,
                memory,
                failed_prior,
                attempt_number,
                strategy_hint,
                retry_after_malformed=True,
            )
            if not self._validate_diff_format(patch.get("patch_diff", "")):
                logger.error(
                    "[patch_generation] Still malformed after retry — forcing confidence to 0.0"
                )
                patch["confidence"] = 0.0

        # Step 7: confidence check — caller (supervisor) must not deploy below the minimum
        if patch.get("confidence", 0.0) < MINIMUM_CONFIDENCE_TO_DEPLOY:
            logger.warning(
                f"[patch_generation] confidence {patch.get('confidence')} below "
                f"{MINIMUM_CONFIDENCE_TO_DEPLOY} — caller should not deploy"
            )

        logger.info(
            f"[patch_generation] strategy={patch.get('strategy_used')} "
            f"confidence={patch.get('confidence')}"
        )
        return patch

    def _validate_diff_format(self, patch_diff: str) -> bool:
        """
        Validates that patch_diff is valid unified diff format.
        Returns True if valid, False otherwise.

        Checks:
        - Contains at least one --- and +++ header
        - Contains at least one @@ hunk header
        - Has at least one + or - line
        """
        lines = patch_diff.splitlines()
        has_old = any(line.startswith("---") for line in lines)
        has_new = any(line.startswith("+++") for line in lines)
        has_hunk = any(line.startswith("@@") for line in lines)
        has_changes = any(
            line.startswith("+") or line.startswith("-")
            for line in lines
            if not line.startswith("+++") and not line.startswith("---")
        )

        return has_old and has_new and has_hunk and has_changes

    def _log_episode(
        self,
        target_cve: str,
        cwe_classification: str,
        patch_strategy: str,
        patch_diff: str,
        outcome: str,
        failure_reason: str | None = None,
        target_technology: str = "",
        attack_summary: str = "",
    ):
        """
        Logs this patch attempt to blue episodic memory.
        Called after EVERY attempt — success, failure, and regression.
        """
        episode_id = str(uuid.uuid4())
        document = f"{cwe_classification} {patch_strategy} {failure_reason or ''}".strip()
        metadata = {
            "episode_id": episode_id,
            "target_cve": target_cve,
            "target_technology": target_technology,
            "attack_summary": attack_summary[:500],
            "cwe_classification": cwe_classification,
            "patch_strategy": patch_strategy,
            "patch_diff": patch_diff[:500],
            "outcome": outcome,
            "failure_reason": failure_reason or "",
            "timestamp": datetime.now(UTC).isoformat(),
        }
        get_collection(BLUE_EPISODIC).add(
            documents=[document],
            metadatas=[metadata],
            ids=[episode_id],
        )
        logger.info(f"[patch_generation] Logged episode {episode_id} outcome={outcome}")

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _generate_with_llm(
        self,
        vulnerability_analysis: dict,
        source_code: str,
        memory: dict,
        failed_prior: list[dict],
        attempt_number: int,
        strategy_hint: str,
        retry_after_malformed: bool = False,
    ) -> dict:
        """Assembles context within the file's documented budget and calls the patch LLM."""
        system_prompt = _PROMPT_PATH.read_text()

        sections = [
            f"## Vulnerability Analysis\n{json.dumps(vulnerability_analysis, indent=2)}",
            f"## Source Code\n{self._truncate_source(source_code)}",
            f"## Attempt\n{attempt_number} — {strategy_hint}",
        ]

        if memory.get("procedural"):
            docs = "\n".join(r["document"] for r in memory["procedural"])
            sections.append(f"## Procedural Memory (highest priority)\n{docs}")

        if failed_prior:
            reasons = "\n".join(
                r.get("metadata", {}).get("failure_reason", "")
                for r in failed_prior
                if r.get("metadata", {}).get("failure_reason")
            )
            if reasons:
                sections.append(f"## Prior Failed Attempts — do not repeat these\n{reasons}")

        if memory.get("knowledge"):
            docs = "\n".join(r["document"] for r in memory["knowledge"])
            sections.append(f"## Patch Knowledge\n{docs}")

        if retry_after_malformed:
            sections.append(
                "## IMPORTANT\nYour previous response was not a valid unified diff. "
                "patch_diff MUST contain '---'/'+++' headers and at least one '@@' hunk."
            )

        user_msg = "\n\n".join(sections) + "\n\nReturn ONLY the JSON patch object."

        response_text, usage = self.llm.chat(
            role=ModelRole.CODE_GEN,
            task=TaskType.PATCH_GENERATION,
            messages=[{"role": "user", "content": user_msg}],
            system_prompt=system_prompt,
        )
        logger.debug(f"[patch_generation] LLM used {usage.total} tokens")
        return self._parse_json_response(response_text)

    def _truncate_source(self, source_code: str) -> str:
        if len(source_code) <= _MAX_SOURCE_CHARS:
            return source_code
        return (
            source_code[:_MAX_SOURCE_CHARS]
            + f"\n\n[SOURCE TRUNCATED: {len(source_code)} chars -> {_MAX_SOURCE_CHARS} max]"
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
            logger.error(f"[patch_generation] LLM returned non-JSON: {text[:300]}")
            return self._empty_patch()

        for key in _PATCH_KEYS:
            if key not in parsed:
                logger.error(f"[patch_generation] LLM patch missing key '{key}' — using default")
                return self._empty_patch()

        return parsed

    def _empty_patch(self) -> dict:
        """Zero-confidence fallback when the LLM response can't be used."""
        return {
            "patch_diff": "",
            "confidence": 0.0,
            "strategy_used": "none — LLM response unparseable",
            "rationale": "",
        }
