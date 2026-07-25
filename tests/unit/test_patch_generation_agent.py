# =============================================================================
# tests/unit/test_patch_generation_agent.py
# OWNER: Blue Team Hire
# MARKERS: unit (no Ollama or ChromaDB required — all external calls mocked)
# PURPOSE: Tests for PatchGenerationAgent.generate_patch(), _log_episode(),
#          and helpers.
# RUN: pytest tests/unit/test_patch_generation_agent.py -v
# =============================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.blue_team.patch_generation_agent import (
    MINIMUM_CONFIDENCE_TO_DEPLOY,
    PatchGenerationAgent,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VULNERABILITY_ANALYSIS = {
    "cwe_classification": "CWE-89: SQL Injection",
    "vulnerable_file": "vulnerabilities/sqli/source/low.php",
    "vulnerable_function": "query",
    "vulnerable_line": 12,
    "missing_control": "No input sanitization before SQL query",
    "allowed_patch_paths": ["vulnerabilities/sqli/source/low.php"],
    "evidence": "string concatenation of $id into raw SQL",
    "confidence": 0.85,
}

_VALID_DIFF = (
    "--- a/vulnerabilities/sqli/source/low.php\n"
    "+++ b/vulnerabilities/sqli/source/low.php\n"
    "@@ -1,3 +1,3 @@\n"
    '-$query = "SELECT * FROM users WHERE id = " . $id;\n'
    '+$query = $this->prepare("SELECT * FROM users WHERE id = %d", $id);\n'
)

_VALID_PATCH = {
    "patch_diff": _VALID_DIFF,
    "confidence": 0.9,
    "strategy_used": "applied prepared statements",
    "rationale": "CWE-89 requires parameterization",
}

_MALFORMED_PATCH = {
    "patch_diff": "this is not a diff at all",
    "confidence": 0.9,
    "strategy_used": "bogus",
    "rationale": "n/a",
}

_EMPTY_MEMORY = {"procedural": [], "episodic": [], "knowledge": []}


def _make_agent():
    with patch("agents.blue_team.patch_generation_agent.get_client"):
        return PatchGenerationAgent()


def _mock_usage():
    usage = MagicMock()
    usage.total = 150
    return usage


# ---------------------------------------------------------------------------
# generate_patch — happy path
# ---------------------------------------------------------------------------


class TestGeneratePatchHappyPath:
    def test_returns_valid_patch(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_PATCH), _mock_usage()))

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ):
            result = agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php old code ?>")

        assert result["patch_diff"] == _VALID_DIFF
        assert result["confidence"] == 0.9

    def test_all_required_keys_present(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_PATCH), _mock_usage()))

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ):
            result = agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php old code ?>")

        for key in ["patch_diff", "confidence", "strategy_used", "rationale"]:
            assert key in result

    def test_filters_procedural_memory_by_cwe_type(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_PATCH), _mock_usage()))

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ) as mock_retrieval:
            agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        mock_retrieval.assert_called_once_with(
            "CWE-89: SQL Injection",
            team="blue",
            n_results_each=3,
            metadata_filter={"cwe_type": "CWE-89"},
        )


# ---------------------------------------------------------------------------
# generate_patch — prior failures expand retrieval
# ---------------------------------------------------------------------------


class TestPriorFailuresExpandRetrieval:
    def test_many_prior_failures_expands_procedural(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_PATCH), _mock_usage()))

        failed_episodic = [
            {
                "document": "sql injection patch failed",
                "metadata": {"outcome": "FAILURE", "failure_reason": "broke login"},
                "distance": 0.1,
            },
            {
                "document": "sql injection patch failed again",
                "metadata": {"outcome": "FAILURE", "failure_reason": "still exploitable"},
                "distance": 0.2,
            },
        ]
        memory_with_failures = {"procedural": [], "episodic": failed_episodic, "knowledge": []}

        call_count = {"n": 0}

        def fake_retrieval(*args, **kwargs):
            call_count["n"] += 1
            return memory_with_failures

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            side_effect=fake_retrieval,
        ):
            agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        assert call_count["n"] >= 2

    def test_failure_reasons_included_in_prompt(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=(json.dumps(_VALID_PATCH), _mock_usage()))

        failed_episodic = [
            {
                "document": "sql injection patch failed",
                "metadata": {"outcome": "FAILURE", "failure_reason": "broke login flow"},
                "distance": 0.1,
            }
        ]
        memory = {"procedural": [], "episodic": failed_episodic, "knowledge": []}

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval", return_value=memory
        ):
            agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        prompt_sent = agent.llm.chat.call_args.kwargs["messages"][0]["content"]
        assert "broke login flow" in prompt_sent


# ---------------------------------------------------------------------------
# generate_patch — malformed diff retry
# ---------------------------------------------------------------------------


class TestMalformedDiffRetry:
    def test_malformed_diff_retries_once_then_succeeds(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(
            side_effect=[
                (json.dumps(_MALFORMED_PATCH), _mock_usage()),
                (json.dumps(_VALID_PATCH), _mock_usage()),
            ]
        )

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ):
            result = agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        assert agent.llm.chat.call_count == 2
        assert result["patch_diff"] == _VALID_DIFF

    def test_still_malformed_after_retry_forces_zero_confidence(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=(json.dumps(_MALFORMED_PATCH), _mock_usage()))

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ):
            result = agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        assert agent.llm.chat.call_count == 2
        assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# _validate_diff_format
# ---------------------------------------------------------------------------


class TestValidateDiffFormat:
    def test_valid_diff_passes(self):
        agent = _make_agent()
        assert agent._validate_diff_format(_VALID_DIFF) is True

    def test_missing_hunk_header_fails(self):
        agent = _make_agent()
        no_hunk = "--- a/f.php\n+++ b/f.php\n-old\n+new\n"
        assert agent._validate_diff_format(no_hunk) is False

    def test_no_changes_fails(self):
        agent = _make_agent()
        no_changes = "--- a/f.php\n+++ b/f.php\n@@ -1 +1 @@\n"
        assert agent._validate_diff_format(no_changes) is False

    def test_plain_text_fails(self):
        agent = _make_agent()
        assert agent._validate_diff_format("just some text") is False


# ---------------------------------------------------------------------------
# JSON parsing fallback
# ---------------------------------------------------------------------------


class TestParseJsonResponse:
    def test_non_json_response_returns_empty_patch(self):
        agent = _make_agent()
        agent.llm.chat = MagicMock(return_value=("not json", _mock_usage()))

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ):
            result = agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        # non-JSON triggers the malformed-diff retry path too (empty patch_diff fails validation)
        assert result["confidence"] == 0.0
        assert result["patch_diff"] == ""

    def test_strips_markdown_fences(self):
        agent = _make_agent()
        fenced = f"```json\n{json.dumps(_VALID_PATCH)}\n```"
        agent.llm.chat = MagicMock(return_value=(fenced, _mock_usage()))

        with patch(
            "agents.blue_team.patch_generation_agent.parallel_retrieval",
            return_value=_EMPTY_MEMORY,
        ):
            result = agent.generate_patch(_VULNERABILITY_ANALYSIS, "<?php ?>")

        assert result["patch_diff"] == _VALID_DIFF


# ---------------------------------------------------------------------------
# Confidence threshold constant
# ---------------------------------------------------------------------------


class TestConfidenceConstant:
    def test_minimum_confidence_is_point_six(self):
        assert MINIMUM_CONFIDENCE_TO_DEPLOY == 0.6


# ---------------------------------------------------------------------------
# _log_episode
# ---------------------------------------------------------------------------


class TestLogEpisode:
    def test_writes_to_blue_episodic_with_required_fields(self):
        agent = _make_agent()
        mock_collection = MagicMock()

        with patch(
            "agents.blue_team.patch_generation_agent.get_collection",
            return_value=mock_collection,
        ) as mock_get_collection:
            agent._log_episode(
                target_cve="CVE-2024-1234",
                cwe_classification="CWE-89: SQL Injection",
                patch_strategy="applied prepared statements",
                patch_diff=_VALID_DIFF,
                outcome="success",
            )

        mock_get_collection.assert_called_once_with("blue_episodic")
        mock_collection.add.assert_called_once()
        metadata = mock_collection.add.call_args.kwargs["metadatas"][0]
        assert metadata["target_cve"] == "CVE-2024-1234"
        assert metadata["cwe_classification"] == "CWE-89: SQL Injection"
        assert metadata["outcome"] == "success"
        assert metadata["failure_reason"] == ""

    def test_records_failure_reason_on_failure(self):
        agent = _make_agent()
        mock_collection = MagicMock()

        with patch(
            "agents.blue_team.patch_generation_agent.get_collection",
            return_value=mock_collection,
        ):
            agent._log_episode(
                target_cve="CVE-2024-1234",
                cwe_classification="CWE-89: SQL Injection",
                patch_strategy="applied prepared statements",
                patch_diff=_VALID_DIFF,
                outcome="failure",
                failure_reason="broke login flow",
            )

        metadata = mock_collection.add.call_args.kwargs["metadatas"][0]
        assert metadata["failure_reason"] == "broke login flow"

    def test_truncates_long_patch_diff_in_metadata(self):
        agent = _make_agent()
        mock_collection = MagicMock()
        long_diff = "x" * 1000

        with patch(
            "agents.blue_team.patch_generation_agent.get_collection",
            return_value=mock_collection,
        ):
            agent._log_episode(
                target_cve="CVE-2024-1234",
                cwe_classification="CWE-89: SQL Injection",
                patch_strategy="applied prepared statements",
                patch_diff=long_diff,
                outcome="success",
            )

        metadata = mock_collection.add.call_args.kwargs["metadatas"][0]
        assert len(metadata["patch_diff"]) == 500
