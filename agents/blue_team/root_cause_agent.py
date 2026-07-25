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

import json
from pathlib import Path

from loguru import logger

from agents.shared.mcp_transport import BlueTeamTransport
from agents.shared.memory import parallel_retrieval
from agents.shared.ollama_client import ModelRole, TaskType, get_client

_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "prompts" / "blue_team" / "root_cause_agent_v1.md"
)

_ANALYSIS_KEYS = [
    "cwe_classification",
    "vulnerable_file",
    "vulnerable_function",
    "vulnerable_line",
    "missing_control",
    "allowed_patch_paths",
    "evidence",
    "confidence",
]

_MAX_SOURCE_FILES = 3  # cap how many candidate files get read into context


class RootCauseAgent:
    """
    Root Cause Agent for the Blue Team pipeline.

    Identifies the specific vulnerable code path and CWE classification.
    Outputs allowed_patch_paths which becomes the mcp_transport whitelist.
    """

    def __init__(self):
        self.transport = BlueTeamTransport()
        self.llm = get_client()

    def analyze(
        self,
        attack_summary: dict,
        container_id: str,
        candidate_files: list[str] | None = None,
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
        logger.info(
            f"[root_cause] Analyzing endpoint={attack_summary.get('target_endpoint')} "
            f"container={container_id}"
        )

        # Step 1: candidate files — explicit hint, or inferred from the attack summary
        files = (candidate_files or self._infer_candidate_files(attack_summary))[:_MAX_SOURCE_FILES]

        # Step 2: read source via MCP (read-only)
        source_code = self._read_sources(container_id, files)

        # Step 3: parallel memory retrieval — patch_knowledge for relevant CWEs
        query = (
            " ".join(
                filter(
                    None,
                    [
                        attack_summary.get("attack_goal_achieved", ""),
                        attack_summary.get("payload_observed", ""),
                    ],
                )
            )
            or "vulnerability"
        )
        memory = parallel_retrieval(query, team="blue", n_results_each=3)

        # Step 4: LLM root cause analysis
        analysis = self._analyze_with_llm(attack_summary, source_code, files, memory)

        # Step 5 + 6: validate schema (allowed_patch_paths non-empty) before returning
        self._validate_output(analysis)

        logger.info(
            f"[root_cause] {analysis.get('cwe_classification')} "
            f"file={analysis.get('vulnerable_file')} confidence={analysis.get('confidence')}"
        )
        return analysis

    def _validate_output(self, output: dict) -> bool:
        """
        Validates that the vulnerability analysis matches the required schema.
        Returns True if valid, raises ValueError if not.
        """
        for key in _ANALYSIS_KEYS:
            if key not in output:
                raise ValueError(f"Vulnerability analysis missing required key: '{key}'")

        # allowed_patch_paths must be a non-empty list of relative paths
        if not isinstance(output["allowed_patch_paths"], list) or not output["allowed_patch_paths"]:
            raise ValueError("allowed_patch_paths must be a non-empty list")

        return True

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _infer_candidate_files(self, attack_summary: dict) -> list[str]:
        """Best-effort mapping from the attacked endpoint to a source file path."""
        endpoint = (attack_summary.get("target_endpoint") or "").split("?", 1)[0]
        path = endpoint.lstrip("/")
        if not path:
            return []
        if path.endswith("/"):
            path += "index.php"
        return [path]

    def _read_sources(self, container_id: str, files: list[str]) -> str:
        """Reads each candidate file via MCP, skipping ones that fail to read."""
        if not files:
            return "(no candidate source files identified from the attack summary)"

        sections = []
        for path in files:
            result = self.transport.read_source_file(container_id, path)
            if result.success and result.raw_output.strip():
                sections.append(f"### {path}\n{result.raw_output}")
            else:
                logger.warning(f"[root_cause] Could not read source at '{path}': {result.error}")

        return "\n\n".join(sections) if sections else "(none of the candidate files could be read)"

    def _analyze_with_llm(
        self,
        attack_summary: dict,
        source_code: str,
        candidate_files: list[str],
        memory: dict,
    ) -> dict:
        """Assembles context from the attack summary + source and calls the root-cause LLM."""
        system_prompt = _PROMPT_PATH.read_text()

        sections = [
            f"## Attack Summary\n{json.dumps(attack_summary, indent=2)}",
            f"## Candidate Files\n{candidate_files}",
            f"## Source Code\n{source_code}",
        ]

        if memory.get("procedural"):
            docs = "\n".join(r["document"] for r in memory["procedural"])
            sections.append(f"## Procedural Memory (highest priority)\n{docs}")

        if memory.get("episodic"):
            docs = "\n".join(r["document"] for r in memory["episodic"])
            sections.append(f"## Episodic Memory (prior patch attempts)\n{docs}")

        if memory.get("knowledge"):
            docs = "\n".join(r["document"] for r in memory["knowledge"])
            sections.append(f"## Patch Knowledge\n{docs}")

        user_msg = "\n\n".join(sections) + "\n\nReturn ONLY the JSON vulnerability analysis."

        response_text, usage = self.llm.chat(
            role=ModelRole.REASONING,
            task=TaskType.ROOT_CAUSE,
            messages=[{"role": "user", "content": user_msg}],
            system_prompt=system_prompt,
        )
        logger.debug(f"[root_cause] LLM used {usage.total} tokens")
        return self._parse_json_response(response_text, candidate_files)

    def _parse_json_response(self, text: str, candidate_files: list[str]) -> dict:
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
            logger.error(f"[root_cause] LLM returned non-JSON: {text[:300]}")
            return self._fallback_analysis(candidate_files)

        for key in _ANALYSIS_KEYS:
            if key not in parsed:
                logger.error(f"[root_cause] LLM analysis missing key '{key}' — using fallback")
                return self._fallback_analysis(candidate_files)

        return parsed

    def _fallback_analysis(self, candidate_files: list[str]) -> dict:
        """
        Zero-confidence fallback when the LLM response can't be used.

        allowed_patch_paths falls back to whatever candidate files were actually
        read rather than an empty list — an empty list would fail
        _validate_output's non-empty check even though we do have a best-effort
        scope guess. If there were no candidates at all, this legitimately
        propagates as a validation failure — there's nothing to patch.
        """
        return {
            "cwe_classification": "UNKNOWN",
            "vulnerable_file": candidate_files[0] if candidate_files else "",
            "vulnerable_function": "",
            "vulnerable_line": 0,
            "missing_control": "Could not be determined — LLM response unparseable",
            "allowed_patch_paths": candidate_files,
            "evidence": "",
            "confidence": 0.0,
        }
