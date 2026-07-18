"""
Red Team pipeline runner — issue #41 gate.
Runs: init → recon → exploitation → verification against DVWA.
"""

import json
import sys

from agents.red_team.state import AttackPhase, RedTeamState
from agents.red_team.supervisor import create_red_team_graph

TARGET_URL = "http://localhost:8080"
TARGET_CVE = "CVE-2019-9053"  # DVWA SQLi — well-known, in CVE-Bench


def main():
    print(f"[runner] Starting Red Team pipeline against {TARGET_URL}")
    print(f"[runner] Target CVE: {TARGET_CVE}")

    initial_state: RedTeamState = {
        "target_url": TARGET_URL,
        "target_cve": TARGET_CVE,
        "trace_id": "",
        "phase": AttackPhase.INIT,
        "step_count": 0,
        "token_count": 0,
        "retry_count": 0,
        "elapsed_seconds": 0.0,
        "recon_summary": None,
        "cve_matches": [],
        "attack_plan": None,
        "payload_used": None,
        "server_response": None,
        "exploit_claimed_success": None,
        "grader_confirmed": False,
        "attack_goals_achieved": [],
        "verification_confidence": 0.0,
        "outcome": None,
        "failure_reason": None,
        "supervisor_notes": [],
    }

    graph = create_red_team_graph()

    try:
        final_state = graph.invoke(initial_state)
    except Exception as e:
        print(f"[runner] Pipeline error: {e}", file=sys.stderr)
        raise

    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)
    print(f"Trace ID:              {final_state.get('trace_id')}")
    print(f"Outcome:               {final_state.get('outcome')}")
    print(f"Phase:                 {final_state.get('phase')}")
    print(f"Steps used:            {final_state.get('step_count')}")
    print(f"Grader confirmed:      {final_state.get('grader_confirmed')}")
    print(f"Attack goals achieved: {final_state.get('attack_goals_achieved')}")
    print(f"Payload used:          {final_state.get('payload_used', '')[:120]}")
    print(f"Failure reason:        {final_state.get('failure_reason')}")
    print("\nSupervisor notes:")
    for note in final_state.get("supervisor_notes", []):
        print(f"  - {note}")

    print("\nFull state (JSON):")
    serialisable = {
        k: str(v) if not isinstance(v, str | int | float | bool | list | dict | type(None)) else v
        for k, v in final_state.items()
    }
    print(json.dumps(serialisable, indent=2))

    return 0 if str(final_state.get("outcome", "")).lower() == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
