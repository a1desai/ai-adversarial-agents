# =============================================================================
# tests/unit/test_memory.py
# OWNER: Lead / any hire
# MARKERS: unit (no Ollama or Docker required)
# PURPOSE: Tests for agents/shared/memory.py
#          Verifies collection initialization, schema, and retrieval helpers.
# RUN: pytest tests/unit/test_memory.py -v
# =============================================================================

from unittest.mock import patch

import pytest

from agents.shared.memory import (
    ALL_COLLECTIONS,
    BLUE_EPISODIC,
    BLUE_PROCEDURAL,
    CVE_KNOWLEDGE,
    PATCH_KNOWLEDGE,
    RED_EPISODIC,
    RED_PROCEDURAL,
    get_collection,
    parallel_retrieval,
)

# ---------------------------------------------------------------------------
# Collection Constants
# ---------------------------------------------------------------------------


class TestCollectionConstants:
    def test_all_six_collections_defined(self):
        assert len(ALL_COLLECTIONS) == 6

    def test_all_collection_names_are_strings(self):
        for name in ALL_COLLECTIONS:
            assert isinstance(name, str)
            assert len(name) > 0

    def test_red_and_blue_collections_distinct(self):
        red_cols = {CVE_KNOWLEDGE, RED_EPISODIC, RED_PROCEDURAL}
        blue_cols = {PATCH_KNOWLEDGE, BLUE_EPISODIC, BLUE_PROCEDURAL}
        assert red_cols.isdisjoint(blue_cols), "Red and Blue collections must not overlap"

    def test_unknown_collection_raises(self, in_memory_chroma, mock_embedding_function):
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            with pytest.raises(ValueError, match="Unknown collection"):
                get_collection("nonexistent_collection")


# ---------------------------------------------------------------------------
# Collection Initialization
# ---------------------------------------------------------------------------


class TestCollectionInitialization:
    def test_get_collection_creates_if_not_exists(self, in_memory_chroma, mock_embedding_function):
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            col = get_collection(CVE_KNOWLEDGE)
            assert col is not None
            assert col.count() == 0

    def test_get_collection_idempotent(self, in_memory_chroma, mock_embedding_function):
        """Calling get_collection twice returns the same collection."""
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            col1 = get_collection(CVE_KNOWLEDGE)
            col2 = get_collection(CVE_KNOWLEDGE)
            assert col1.name == col2.name

    def test_all_collections_initializable(self, in_memory_chroma, mock_embedding_function):
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            for name in ALL_COLLECTIONS:
                col = get_collection(name)
                assert col is not None


# ---------------------------------------------------------------------------
# Dummy Data Ingestion
# ---------------------------------------------------------------------------


class TestDummyDataIngestion:
    def test_ingest_cve_records(self, in_memory_chroma, mock_embedding_function, dummy_cve_records):
        """Verify dummy CVE records can be inserted into ChromaDB."""
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            col = get_collection(CVE_KNOWLEDGE)

            # Insert dummy records
            col.add(
                ids=[r["cve_id"] for r in dummy_cve_records],
                documents=[r["description"] for r in dummy_cve_records],
                metadatas=[
                    {
                        "cve_id": r["cve_id"],
                        "cvss_score": r["cvss_score"],
                        "cwe_ids": ",".join(r["cwe_ids"]),
                    }
                    for r in dummy_cve_records
                ],
            )

            assert col.count() == len(dummy_cve_records)

    def test_query_returns_one_result(
        self, in_memory_chroma, mock_embedding_function, dummy_cve_records
    ):
        """After ingestion, col.query(n_results=1) returns exactly 1 result from the inserted set."""
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            col = get_collection(CVE_KNOWLEDGE)
            col.add(
                ids=[r["cve_id"] for r in dummy_cve_records],
                documents=[r["description"] for r in dummy_cve_records],
                metadatas=[
                    {"cve_id": r["cve_id"], "cwe_ids": ",".join(r["cwe_ids"])}
                    for r in dummy_cve_records
                ],
            )

            results = col.query(query_texts=["SQL injection database"], n_results=1)
            assert len(results["ids"][0]) == 1
            # Result must be one of the inserted CVEs (fake embedder is non-semantic, can't assert which)
            all_ids = {r["cve_id"] for r in dummy_cve_records}
            assert results["ids"][0][0] in all_ids


# ---------------------------------------------------------------------------
# Parallel Retrieval
# ---------------------------------------------------------------------------


class TestParallelRetrieval:
    def test_parallel_retrieval_returns_all_three_keys(
        self, in_memory_chroma, mock_embedding_function
    ):
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            results = parallel_retrieval("SQL injection", team="red", n_results_each=1)
            assert "procedural" in results
            assert "episodic" in results
            assert "knowledge" in results

    def test_parallel_retrieval_invalid_team_raises(
        self, in_memory_chroma, mock_embedding_function
    ):
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
        ):
            with pytest.raises(ValueError, match="team must be"):
                parallel_retrieval("test", team="purple")

    def test_parallel_retrieval_red_uses_red_collections(
        self, in_memory_chroma, mock_embedding_function
    ):
        with (
            patch("agents.shared.memory.get_client", return_value=in_memory_chroma),
            patch(
                "agents.shared.memory.get_embedding_function", return_value=mock_embedding_function
            ),
            patch("agents.shared.memory.query_collection") as mock_query,
        ):
            mock_query.return_value = []
            parallel_retrieval("test query", team="red")
            called_collections = [call.args[0] for call in mock_query.call_args_list]
            assert RED_PROCEDURAL in called_collections
            assert RED_EPISODIC in called_collections
            assert CVE_KNOWLEDGE in called_collections
            # Blue collections should NOT be called
            assert BLUE_PROCEDURAL not in called_collections
