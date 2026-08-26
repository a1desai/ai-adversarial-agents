# =============================================================================
# tests/integration/conftest.py
# OWNER: Eval Hire
# PURPOSE: Integration-specific fixtures for the end-to-end pipeline tests.
#          Provides fake Red Team agents so create_red_team_graph() can run a
#          full recon -> exploitation -> verification -> finalize path with NO
#          network / GPU / Ollama / ChromaDB involvement.
# REFERENCE: Issue #69 — Integration tests (Red Team pipeline)
# NOTE: AI-assisted (drafted with Claude), human-reviewed.
# =============================================================================

import pytest


class FakeReconAgent:
    """Stands in for ReconAgent.run() — returns a fixed structured recon dict."""

    # Class-level knobs individual tests can override before instantiation.
    ports = [{"port": "80/tcp", "state": "open", "service": "http", "version": "Apache 2.4"}]
    confidence = 0.9

    def run(self, target_url: str) -> dict:
        return {
            "ports": list(self.ports),
            "technologies": ["WordPress 6.4", "PHP 8.1"],
            "directories": ["/wp-login.php"],
            "potential_entry_points": ["/wp-admin/admin-ajax.php"],
            "confidence": self.confidence,
        }


class FakeExploitationAgent:
    """Stands in for ExploitationAgent.plan_attack() + execute_payload()."""

    target_service = "http"
    cve_id = "CVE-2024-0001"
    # "SUCCESS" makes exploit_claimed_success True in exploitation_node.
    exec_outcome = "SUCCESS"
    exec_confidence = 0.8

    def plan_attack(self, recon_summary: dict, target_cve: str | None = None) -> dict:
        return {
            "target_service": self.target_service,
            "target_endpoint": "/wp-admin/admin-ajax.php",
            "cve_id": self.cve_id,
            "technique": "SQL injection via UNION-based extraction",
            "confidence": 0.85,
            "rationale": "Fake plan for integration test",
        }

    def execute_payload(self, attack_plan: dict, target_url: str) -> dict:
        return {
            "payload_used": "' UNION SELECT 1,2,3-- -",
            "server_response": "admin:hash extracted",
            "success_indicators": ["union select"],
            "outcome": self.exec_outcome,
            "confidence": self.exec_confidence,
        }


class FakeVerificationAgent:
    """Stands in for VerificationAgent.verify() — grader confirmation result."""

    confirmed = True
    attack_goals_achieved = ["database_access"]
    confidence = 0.9

    def verify(self, target_url: str, target_cve: str, claimed_outcome: dict) -> dict:
        return {
            "confirmed": self.confirmed,
            "attack_goals_achieved": list(self.attack_goals_achieved),
            "grader_response": "confirmed" if self.confirmed else "no goal achieved",
            "confidence": self.confidence,
        }


@pytest.fixture
def fake_red_agents():
    """
    Returns the three fake agent classes. Tests can subclass / tweak class
    attributes and patch them onto agents.red_team.supervisor before driving
    the graph.
    """
    return {
        "ReconAgent": FakeReconAgent,
        "ExploitationAgent": FakeExploitationAgent,
        "VerificationAgent": FakeVerificationAgent,
    }
