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


from agents.shared.ollama_client import get_client

MINIMUM_CONFIDENCE_TO_DEPLOY = 0.6


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
        # Step 1: Parallel memory retrieval
        # TODO: cwe = vulnerability_analysis.get("cwe_classification", "unknown")
        # TODO: memory = parallel_retrieval(query=cwe, team="blue", n_results_each=3)
        # Metadata filter: {"cwe_type": cwe_type_short} for blue_procedural

        # Step 2: Check prior failed attempts (avoid repeating bad patches)
        # TODO: query blue_episodic for this CVE with outcome=FAILURE
        # Pass failure reasons to LLM so it doesn't repeat the same mistake

        # Step 3: On retry, use a different strategy
        # attempt 1 → primary procedural memory approach
        # attempt 2 → alternative CWE remediation pattern
        # attempt 3 → most conservative approach (most minimal possible change)

        # Step 4: Assemble context within token budget
        # 30% memory | 30% source code + vulnerability analysis | 40% reasoning
        # Load system prompt from: /prompts/blue_team/patch_generation_agent_v1.md

        # Step 5: LLM patch generation
        # TODO: response, usage = self.llm.chat(
        #     role=ModelRole.CODE_GEN,
        #     task=TaskType.PATCH_GENERATION,
        #     messages=[...],
        #     system_prompt=...,
        # )

        # Step 6: Parse and validate diff format
        # TODO: validate response is valid unified diff (starts with ---, +++)
        # Reject and retry if malformed

        # Step 7: Confidence check
        # TODO: parse confidence from LLM output
        # If < MINIMUM_CONFIDENCE_TO_DEPLOY: log warning, caller should not deploy

        raise NotImplementedError("PatchGenerationAgent.generate_patch() not yet implemented")

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
    ):
        """
        Logs this patch attempt to blue episodic memory.
        Called after EVERY attempt — success, failure, and regression.
        """
        # TODO: get_collection(BLUE_EPISODIC).add(...)
        # See memory.py schema comments for full field list
        raise NotImplementedError("_log_episode() not yet implemented")
