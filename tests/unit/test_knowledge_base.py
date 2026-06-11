# =============================================================================
# tests/unit/test_knowledge_base.py
# OWNER: Knowledge Base Hire
# MARKERS: unit (no Ollama / Docker / network — uses in-memory Chroma + stubs)
# PURPOSE: Tests for the ingestion pipeline — nvd_scraper (#9), chunker (#10),
#          embedder (#11), run_ingestion (#12).
# RUN: pytest tests/unit/test_knowledge_base.py -v
# =============================================================================

from types import SimpleNamespace

import pytest

from knowledge_base.chunker import (
    CVE_CHUNK_TYPES,
    PROSE_CHUNK_TOKENS,
    chunk_cve,
    chunk_patch,
)
from knowledge_base.embedder import embed_chunks
from knowledge_base.nvd_scraper import WEB_APP_CWES, fetch_cves, normalize_cve

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_cve():
    return {
        "cve_id": "CVE-2024-1001",
        "description": "A SQL injection vulnerability in ExampleCMS 3.2 allows "
        "unauthenticated attackers to execute arbitrary SQL.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-89"],
        "affected_technology": "ExampleCMS 3.2",
        "published_date": "2024-01-15",
        "exploit_methodology": "GET /search?id=1' OR '1'='1\nUNION SELECT user,pass,3 FROM users--",
        "patch_summary": "Use prepared statements. Cast id to int.",
        "references": ["https://github.com/example/examplecms/commit/abc123"],
    }


def _collection(chroma_client, embed_fn, name):
    # Unique name per call — chromadb's EphemeralClient is process-cached, so
    # reusing a name would leak state across tests.
    return chroma_client.get_or_create_collection(name=name, embedding_function=embed_fn)


# ---------------------------------------------------------------------------
# nvd_scraper (#9)
# ---------------------------------------------------------------------------


class TestNvdScraper:
    def _fake_raw(self, cve_id, cwe, score=9.8):
        return SimpleNamespace(
            id=cve_id,
            descriptions=[SimpleNamespace(lang="en", value=f"desc for {cve_id}")],
            v31score=score,
            v31vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe=[SimpleNamespace(value=cwe)],
            published="2024-01-01T00:00:00",
            references=[SimpleNamespace(url="https://example.com/patch")],
        )

    def test_normalize_maps_schema(self):
        cve = normalize_cve(self._fake_raw("CVE-2024-0001", "CWE-89"))
        assert cve["cve_id"] == "CVE-2024-0001"
        assert cve["cvss_score"] == 9.8
        assert cve["cwe_ids"] == ["CWE-89"]
        assert cve["description"] == "desc for CVE-2024-0001"
        assert cve["references"] == ["https://example.com/patch"]
        # NVD-unavailable fields are present but empty for downstream enrichment.
        assert cve["patch_summary"] == ""
        assert cve["exploit_methodology"] == ""

    def test_fetch_filters_non_web_app_cwes(self):
        # CWE-89 (web app) kept; CWE-119 (buffer overflow) dropped by allowlist.
        page = [
            self._fake_raw("CVE-2024-0001", "CWE-89"),
            self._fake_raw("CVE-2024-0002", "CWE-119"),
        ]
        # searcher is called once per allowlisted CWE; serve the page for CWE-89.
        cves = fetch_cves(
            limit=10,
            delay=0,
            _searcher=lambda **kw: page if kw["cweId"] == "CWE-89" else [],
        )
        ids = {c["cve_id"] for c in cves}
        assert ids == {"CVE-2024-0001"}

    def test_fetch_filters_below_min_cvss(self):
        page = [self._fake_raw("CVE-2024-0003", "CWE-79", score=7.5)]
        cves = fetch_cves(
            limit=10,
            min_cvss=9.0,
            delay=0,
            _searcher=lambda **kw: page if kw["cweId"] == "CWE-79" else [],
        )
        assert cves == []

    def test_fetch_respects_limit(self):
        page = [self._fake_raw(f"CVE-2024-{i:04d}", "CWE-89") for i in range(5)]
        cves = fetch_cves(
            limit=3,
            delay=0,
            _searcher=lambda **kw: page if kw["cweId"] == "CWE-89" else [],
        )
        assert len(cves) == 3

    def test_fetch_dedupes_same_cve_across_cwe_queries(self):
        # A single CVE can be mapped to several CWEs, so the per-CWE queries can
        # each return it. fetch_cves keys on cve_id, so it must appear exactly
        # once — without dedup this same object would land in the result twice.
        shared = self._fake_raw("CVE-2024-0001", "CWE-89")
        cves = fetch_cves(
            limit=10,
            delay=0,
            _searcher=lambda **kw: [shared] if kw["cweId"] in ("CWE-89", "CWE-79") else [],
        )
        assert [c["cve_id"] for c in cves] == ["CVE-2024-0001"]

    def test_allowlist_contains_core_web_classes(self):
        for cwe in ("CWE-89", "CWE-79", "CWE-22", "CWE-434"):
            assert cwe in WEB_APP_CWES


# ---------------------------------------------------------------------------
# chunker (#10)
# ---------------------------------------------------------------------------


class TestChunker:
    def test_three_chunks_per_cve(self, sample_cve):
        chunks = chunk_cve(sample_cve)
        assert len(chunks) == 3
        assert {c["metadata"]["chunk_type"] for c in chunks} == set(CVE_CHUNK_TYPES)

    def test_chunk_ids_are_deterministic(self, sample_cve):
        assert [c["id"] for c in chunk_cve(sample_cve)] == [
            "CVE-2024-1001::description",
            "CVE-2024-1001::technical",
            "CVE-2024-1001::reference",
        ]

    def test_metadata_is_chroma_scalar_safe(self, sample_cve):
        for chunk in chunk_cve(sample_cve):
            for value in chunk["metadata"].values():
                assert isinstance(value, str | int | float | bool)
        # cwe_ids list collapsed to a CSV string
        desc = chunk_cve(sample_cve)[0]
        assert desc["metadata"]["cwe_ids"] == "CWE-89"
        assert desc["metadata"]["primary_cwe"] == "CWE-89"

    def test_exploit_methodology_kept_atomic(self, sample_cve):
        technical = next(
            c for c in chunk_cve(sample_cve) if c["metadata"]["chunk_type"] == "technical"
        )
        # The full payload (newline-separated steps) survives intact.
        assert "UNION SELECT user,pass,3 FROM users--" in technical["document"]

    def test_long_prose_windows_with_overlap(self):
        long_desc = " ".join(f"w{i}" for i in range(PROSE_CHUNK_TOKENS + 200))
        cve = {"cve_id": "CVE-2024-9999", "cwe_ids": ["CWE-79"], "description": long_desc}
        chunks = chunk_cve(cve)
        desc_chunks = [c for c in chunks if c["metadata"]["chunk_type"] == "description"]
        assert len(desc_chunks) >= 2  # windowed
        # Overlap: last 50 tokens of window 0 reappear at the start of window 1.
        w0 = desc_chunks[0]["document"].split()
        w1 = desc_chunks[1]["document"].split()
        assert w0[-50:] == w1[:50]

    def test_chunk_patch_builds_patch_knowledge(self, sample_cve):
        patch = chunk_patch(sample_cve)
        assert len(patch) == 1
        assert patch[0]["id"] == "CVE-2024-1001::patch"
        assert patch[0]["metadata"]["chunk_type"] == "patch"
        assert "prepared statements" in patch[0]["document"]

    def test_chunk_patch_empty_when_no_patch_content(self):
        cve = {"cve_id": "CVE-2024-0000", "cwe_ids": ["CWE-89"], "references": []}
        assert chunk_patch(cve) == []

    def test_missing_cve_id_raises(self):
        with pytest.raises(ValueError):
            chunk_cve({"description": "no id"})


# ---------------------------------------------------------------------------
# embedder (#11)
# ---------------------------------------------------------------------------


class TestEmbedder:
    def test_inserts_chunks(self, in_memory_chroma, mock_embedding_function, sample_cve):
        col = _collection(in_memory_chroma, mock_embedding_function, "ins")
        n = embed_chunks(chunk_cve(sample_cve), collection=col)
        assert n == 3
        assert col.count() == 3

    def test_idempotent_rerun_no_duplicates(
        self, in_memory_chroma, mock_embedding_function, sample_cve
    ):
        col = _collection(in_memory_chroma, mock_embedding_function, "idem")
        chunks = chunk_cve(sample_cve)
        embed_chunks(chunks, collection=col)
        embed_chunks(chunks, collection=col)  # re-run
        embed_chunks(chunks, collection=col)  # and again
        assert col.count() == 3  # upsert overwrote, did not duplicate

    def test_empty_chunks_is_noop(self, in_memory_chroma, mock_embedding_function):
        col = _collection(in_memory_chroma, mock_embedding_function, "empty")
        assert embed_chunks([], collection=col) == 0
        assert col.count() == 0

    def test_rejects_malformed_chunk(self, in_memory_chroma, mock_embedding_function):
        col = _collection(in_memory_chroma, mock_embedding_function, "malformed")
        with pytest.raises(ValueError):
            embed_chunks([{"id": "x", "document": "y"}], collection=col)  # no metadata


# ---------------------------------------------------------------------------
# run_ingestion (#12) — offline path
# ---------------------------------------------------------------------------


class TestRunIngestion:
    def test_ingest_loads_both_collections(
        self, in_memory_chroma, mock_embedding_function, sample_cve, monkeypatch
    ):
        from knowledge_base import run_ingestion

        cve_col = _collection(in_memory_chroma, mock_embedding_function, "cve")
        patch_col = _collection(in_memory_chroma, mock_embedding_function, "patch")

        # Route embed_chunks to our ephemeral collections by name.
        from knowledge_base.embedder import CVE_KNOWLEDGE

        def fake_embed(chunks, collection_name=CVE_KNOWLEDGE, *, collection=None):
            target = cve_col if collection_name == CVE_KNOWLEDGE else patch_col
            from knowledge_base.embedder import embed_chunks as real

            return real(chunks, collection=target)

        monkeypatch.setattr(run_ingestion, "embed_chunks", fake_embed)

        summary = run_ingestion.ingest([sample_cve])
        assert summary["records"] == 1
        assert summary["cve_knowledge_chunks"] == 3
        assert summary["patch_knowledge_chunks"] == 1
        assert cve_col.count() == 3
        assert patch_col.count() == 1
