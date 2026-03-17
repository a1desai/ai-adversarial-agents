# =============================================================================
# agents/red_team/state.py
# OWNER: Red Team Hire
# PURPOSE: LangGraph state definition for the Red Team pipeline.
#          Every agent reads from and writes to this shared state object.
# =============================================================================

from typing import TypedDict, Optional
from enum import Enum


class AttackPhase(str, Enum):
    INIT          = "init"
    RECON         = "recon"
    EXPLOITATION  = "exploitation"
    VERIFICATION  = "verification"
    COMPLETE      = "complete"
    FAILED        = "failed"


class AttackOutcome(str, Enum):
    SUCCESS  = "success"
    FAILURE  = "failure"
    PARTIAL  = "partial"
    TIMEOUT  = "timeout"


class RedTeamState(TypedDict):
    # Target info
    target_url:         str
    target_cve:         Optional[str]       # set after CVE is identified

    # Engagement tracking
    trace_id:           str                 # UUID — set by supervisor at start
    phase:              AttackPhase
    step_count:         int                 # hard cap: 30
    token_count:        int                 # hard cap: 50,000
    retry_count:        int                 # hard cap: 3
    elapsed_seconds:    float               # hard cap: 900 (15 min)

    # Recon output (filled by ReconAgent)
    recon_summary:      Optional[dict]      # structured: {ports, services, technologies}

    # Exploitation (filled by ExploitationAgent)
    cve_matches:        list[dict]          # CVEs retrieved from memory
    attack_plan:        Optional[dict]      # proposed attack strategy
    payload_used:       Optional[str]       # exact payload/command sequence
    server_response:    Optional[str]       # truncated server response

    # Verification (filled by VerificationAgent)
    grader_confirmed:   bool                # True only if CVE-Bench grader confirms
    attack_goals_achieved: list[str]        # e.g. ["remote_code_execution"]

    # Final result
    outcome:            Optional[AttackOutcome]
    failure_reason:     Optional[str]

    # Supervisor internal
    supervisor_notes:   list[str]           # routing decisions log