# =============================================================================
# knowledge_base/run_ingestion.py
# OWNER: Knowledge Base Hire
# PURPOSE: End-to-end CVE ingestion — wires nvd_scraper (#9) + chunker (#10)
#          + embedder (#11) into one pipeline and loads ChromaDB. (Issue #12)
# =============================================================================
#
# FLOW:
#   fetch CVEs  ->  chunk each CVE  ->  embed into cve_knowledge
#                \-> chunk patches  ->  embed into patch_knowledge
#
# PHASE 1 DELIVERABLE:
#   python knowledge_base/run_ingestion.py --limit 100 --min-cvss 9.0
#   Expected: "Loaded 100 CVE records into cve_knowledge collection"
#
# Requires Ollama running with nomic-embed-text (ChromaDB embeds on insert).
# Use --source dummy to run fully offline against dummy_data/ (no NVD, but
# still needs Ollama for the embedding function).
# =============================================================================

from __future__ import annotations

import argparse
import json
from pathlib import Path

from loguru import logger

from agents.shared.memory import CVE_KNOWLEDGE, PATCH_KNOWLEDGE, get_collection
from knowledge_base.chunker import chunk_cve, chunk_patch
from knowledge_base.embedder import embed_chunks
from knowledge_base.nvd_scraper import fetch_cves

DUMMY_CVE_PATH = Path(__file__).parent.parent / "dummy_data" / "cve_records" / "cve_records.json"


def _load_dummy_cves() -> list[dict]:
    """Load the offline dummy CVE records (for testing without NVD)."""
    with open(DUMMY_CVE_PATH) as f:
        cves = json.load(f)
    for cve in cves:
        cve.setdefault("source", "dummy")
    logger.info(f"[ingest] Loaded {len(cves)} dummy CVE records from {DUMMY_CVE_PATH}")
    return cves


def ingest(cves: list[dict]) -> dict[str, int]:
    """Chunk and embed a list of CVE records into both collections.

    Returns a summary dict with the number of records and chunks loaded into
    each collection.
    """
    cve_chunks: list[dict] = []
    patch_chunks: list[dict] = []
    for cve in cves:
        cve_chunks.extend(chunk_cve(cve))
        patch_chunks.extend(chunk_patch(cve))

    n_cve = embed_chunks(cve_chunks, CVE_KNOWLEDGE)
    n_patch = embed_chunks(patch_chunks, PATCH_KNOWLEDGE)

    return {
        "records": len(cves),
        "cve_knowledge_chunks": n_cve,
        "patch_knowledge_chunks": n_patch,
    }


def smoke_query(query: str = "SQL injection", expect_cwe: str = "CWE-89") -> bool:
    """Post-ingestion sanity check (issue #12).

    Queries ``cve_knowledge`` and confirms at least one returned chunk is mapped
    to ``expect_cwe``. Returns True on success.
    """
    col = get_collection(CVE_KNOWLEDGE)
    if col.count() == 0:
        logger.error("[ingest] cve_knowledge is empty — nothing to query.")
        return False

    results = col.query(
        query_texts=[query],
        n_results=min(5, col.count()),
        include=["metadatas", "documents"],
    )
    metadatas = results["metadatas"][0]
    hit = any(expect_cwe in (m.get("cwe_ids") or "") for m in metadatas)

    if hit:
        logger.info(f"[ingest] ✓ Smoke query '{query}' returned a {expect_cwe} record.")
    else:
        logger.error(
            f"[ingest] ✗ Smoke query '{query}' returned no {expect_cwe} records. "
            f"Got CWEs: {[m.get('cwe_ids') for m in metadatas]}"
        )
    return hit


def main() -> None:
    parser = argparse.ArgumentParser(description="Full CVE ingestion pipeline (#12)")
    parser.add_argument("--limit", type=int, default=100, help="Max CVEs to fetch")
    parser.add_argument("--min-cvss", type=float, default=9.0, help="Min CVSS base score")
    parser.add_argument(
        "--source",
        choices=("nvd", "dummy"),
        default="nvd",
        help="Where to pull CVEs from (dummy = offline dummy_data/)",
    )
    parser.add_argument(
        "--skip-smoke", action="store_true", help="Skip the post-ingestion smoke query"
    )
    args = parser.parse_args()

    if args.source == "dummy":
        cves = _load_dummy_cves()
    else:
        cves = fetch_cves(limit=args.limit, min_cvss=args.min_cvss)

    summary = ingest(cves)
    logger.info(
        f"[ingest] ✓ Loaded {summary['records']} CVE records into cve_knowledge collection "
        f"({summary['cve_knowledge_chunks']} chunks; "
        f"{summary['patch_knowledge_chunks']} patch chunks)"
    )

    if not args.skip_smoke and not smoke_query():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
