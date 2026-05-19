# =============================================================================
# agents/blue_team/root_cause_agent.py
# OWNER: Blue Team Hire
# PURPOSE: Root Cause Agent — identifies the vulnerable code path, CWE
#          classification, and the minimal patch scope.
# =============================================================================
#
# SCOPE: Receives the Attack Summary from LogAnalysisAgent. Reads source code
#        via MCP. Identifies WHY the exploit succeeded. NEVER sees raw logs.
#
# OUTPUT FORMAT (required — patch_generation_agent depends on this schema):
# {
#   "cwe_classification":   "CWE-89: SQL Injection",
#   "vulnerable_file":      "wp-includes/class-wpdb.php",
#   "vulnerable_function":  "query()",
#   "vulnerable_line":      142,
#   "missing_control":      "No input sanitization before SQL query",
#   "allowed_patch_paths":  ["wp-includes/class-wpdb.php"],  # mcp_transport whitelist
#   "evidence":             "string concatenation at line 142 of $id into raw SQL",
#   "confidence":           0.0-1.0
# }
#
# MEMORY RETRIEVAL:
#   Query patch_knowledge collection with cwe_classification + target_technology
#   Use parallel_retrieval(team="blue") for procedural + episodic + knowledge
#
# REFERENCE: Blue Team Report — Section 4.2.3, 7.3
# =============================================================================

from loguru import logger

from agents.shared.memory import parallel_retrieval, get_collection, PATCH_KNOWLEDGE
from agents.shared.mcp_transport import BlueTeamTransport
from agents.shared.ollama_client import get_client, ModelRole, TaskType


class RootCauseAgent:
    """
    Root Cause Agent for the Blue Team pipeline.

    Identifies the specific vulnerable code path and CWE classification.
    Outputs allowed_patch_paths which becomes the mcp_transport whitelist.
    """

    def __init__(self):
        self.transport = BlueTeamTransport()
        self.llm       = get_client()

    def analyze(
        self,
        attack_summary:     dict,
        container_id:       str,
        candidate_files:    list[str] | None = None,
    ) -> dict:
        """
        Identifies the vulnerable code path that produced the observed attack.

        Args:
            attack_summary:  output of LogAnalysisAgent.analyze()
            container_id:    container to read source code from
            candidate_files: optional hint list of files to start with
                             (e.g., from a CVE advisory). If None, agent infers.

        Returns:
            Vulnerability Analysis dict matching the OUTPUT FORMAT above.
        """
        # TODO (Blue Team Hire):
        # Step 1: Use attack_summary.target_endpoint to identify candidate vulnerable files
        # Step 2: Read source via self.transport.read_source_file(container_id, path)
        # Step 3: Parallel memory retrieval — patch_knowledge for relevant CWEs
        # Step 4: LLM root cause analysis with ROOT_CAUSE task
        # Step 5: Output structured JSON with allowed_patch_paths
        #          (this list becomes the whitelist for mcp_transport.deploy_patch)
        # Step 6: Validate schema before returning

        raise NotImplementedError("RootCauseAgent.analyze() not yet implemented")

    def _validate_output(self, output: dict) -> bool:
        """
        Validates that the vulnerability analysis matches the required schema.
        Returns True if valid, raises ValueError if not.
        """
        required_keys = [
            "cwe_classification",
            "vulnerable_file",
            "vulnerable_function",
            "vulnerable_line",
            "missing_control",
            "allowed_patch_paths",
            "evidence",
            "confidence",
        ]
        for key in required_keys:
            if key not in output:
                raise ValueError(f"Vulnerability analysis missing required key: '{key}'")

        # allowed_patch_paths must be a non-empty list of relative paths
        if not isinstance(output["allowed_patch_paths"], list) or not output["allowed_patch_paths"]:
            raise ValueError("allowed_patch_paths must be a non-empty list")

        return True
