# =============================================================================
# agents/blue_team/state.py
# OWNER: Blue Team Hire
# PURPOSE: LangGraph state definition for the Blue Team pipeline.
# =============================================================================

from typing import TypedDict, Optional
from enum import Enum


class DefensePhase(str, Enum):
    INIT               = "init"
    LOG_ANALYSIS       = "log_analysis"
    ROOT_CAUSE         = "root_cause"
    PATCH_GENERATION   = "patch_generation"
    PATCH_VALIDATION   = "patch_validation"
    COMPLETE           = "complete"
    FAILED             = "failed"


class PatchOutcome(str, Enum):
    SUCCESS    = "success"
    FAILURE    = "failure"
    REGRESSION = "regression"   # patch broke the application
    TIMEOUT    = "timeout"


class BlueTeamState(TypedDict):
    # Trigger info (from hypervisor exploit detection event)
    target_cve:           str
    target_url:           str
    container_id:         str

    # Engagement tracking
    trace_id:             str
    phase:                DefensePhase
    step_count:           int           # hard cap: 30
    token_count:          int           # hard cap: 50,000
    patch_attempt_count:  int           # hard cap: 3
    elapsed_seconds:      float         # hard cap: 900 (15 min)

    # Log Analysis output (filled by LogAnalysisAgent)
    attack_summary:       Optional[dict]
    # {
    #   "target_endpoint":        "/vulnerable/path",
    #   "payload_observed":       "...",
    #   "attack_goal_achieved":   "remote_code_execution",
    #   "http_status_sequence":   [200, 500, 200],
    #   "confidence":             0.0-1.0
    # }

    # Root Cause output (filled by RootCauseAgent)
    vulnerability_analysis: Optional[dict]
    # {
    #   "cwe_classification":   "CWE-89: SQL Injection",
    #   "vulnerable_file":      "wp-includes/class-wpdb.php",
    #   "vulnerable_function":  "query()",
    #   "vulnerable_line":      142,
    #   "missing_control":      "No input sanitization before SQL query",
    #   "allowed_patch_paths":  ["wp-includes/class-wpdb.php"],  # used by mcp_transport whitelist
    #   "confidence":           0.0-1.0
    # }

    # Patch Generation output (filled by PatchGenerationAgent)
    patch_diff:           Optional[str]     # unified diff format
    patch_confidence:     Optional[float]   # 0.0-1.0 — below 0.6 triggers extra retrieval

    # Validation results (filled by PatchValidationAgent)
    patch_applies_cleanly:   bool
    functional_tests_passed: bool
    exploit_blocked:         bool

    # Final result
    outcome:              Optional[PatchOutcome]
    failure_reason:       Optional[str]

    # Supervisor internal
    supervisor_notes:     list[str]