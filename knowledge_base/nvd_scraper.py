# =============================================================================
# knowledge_base/nvd_scraper.py
# OWNER: Knowledge Base Hire
# PURPOSE: Pulls CVE records from NVD API and prepares them for ChromaDB.
# =============================================================================
#
# DATA SOURCE: NIST NVD API (free, no API key needed for basic access)
#   Docs: https://nvd.nist.gov/developers/vulnerabilities
#
# FILTERS:
#   - CVSS 3.1 base score >= 9.0 (critical severity)
#   - Web application vulnerabilities (CWE categories: input validation,
#     injection, path traversal, access control)
#
# OUTPUT: List of structured CVE dicts ready for embedding + ChromaDB insertion
#
# PHASE 1 DELIVERABLE:
#   python knowledge_base/nvd_scraper.py --limit 100 --min-cvss 9.0
#   Expected: "Loaded 100 CVE records into cve_knowledge collection"
# =============================================================================

import argparse
import time
from loguru import logger

# nvdlib wraps the NVD API — free, no key needed
# pip install nvdlib
try:
    import nvdlib
except ImportError:
    raise ImportError("Run: pip install nvdlib")

from agents.shared.memory import get_collection, CVE_KNOWLEDGE, PATCH_KNOWLEDGE
from agents.shared.ollama_client import get_client, ModelRole, TaskType


# CWE IDs we care about (web application vulnerability classes)
TARGET_CWE_IDS = {
    "CWE-89",   # SQL Injection
    "CWE-79",   # XSS
    "CWE-22",   # Path Traversal
    "CWE-78",   # OS Command Injection
    "CWE-287",  # Authentication Issues
    "CWE-285",  # Authorization Issues
    "CWE-434",  # Unrestricted File Upload
    "CWE-502",  # Deserialization
    "CWE-918",  # SSRF
    "CWE-611",  # XXE
}


def fetch_cves(limit: int = 100, min_cvss: float = 9.0) -> list[dict]:
    """
    Fetches CVE records from NVD API.

    Args:
        limit:    max number of CVEs to fetch
        min_cvss: minimum CVSS 3.1 base score

    Returns:
        List of structured CVE dicts
    """
    logger.info(f"[nvd] Fetching CVEs: limit={limit} min_cvss={min_cvss}")

    # TODO (Knowledge Base Hire): implement NVD API fetch using nvdlib
    # Reference: https://github.com/vehemont/nvdlib
    #
    # Example:
    # results = nvdlib.searchCVE(
    #     cvssV3Severity="CRITICAL",
    #     limit=limit,
    # )
    #
    # For each result, extract:
    # - cve_id (r.id)
    # - description (r.descriptions[0].value)
    # - cvss_score (r.v31score or r.v30score)
    # - cwe_ids ([w.value for w in r.cwe] if r.cwe else [])
    # - published_date (r.published)
    # - references (r.references — look for GitHub patch links)
    #
    # Rate limit: NVD allows ~50 requests/30s without API key
    # Add time.sleep(0.6) between requests to stay safe

    raise NotImplementedError("fetch_cves() not yet implemented")


def chunk_cve_document(cve: dict) -> list[dict]:
    """
    Splits a CVE record into retrievable chunks for ChromaDB.

    Three chunks per CVE:
    1. Description chunk — vulnerability description + affected versions
    2. Technical chunk  — CVSS details + CWE classification + exploit methodology
    3. Reference chunk  — patch links, advisories, PoC references

    Returns list of chunk dicts ready for ChromaDB insertion.
    """
    # TODO: implement chunking
    # Each chunk needs: id, document (text), metadata (cve_id, chunk_type, cwe_ids, cvss_score)
    raise NotImplementedError("chunk_cve_document() not yet implemented")


def ingest_to_chromadb(cve_chunks: list[dict], collection_name: str = CVE_KNOWLEDGE):
    """
    Embeds and inserts CVE chunks into ChromaDB.

    Args:
        cve_chunks:      output of chunk_cve_document()
        collection_name: which collection to insert into
                         CVE_KNOWLEDGE for Red Team
                         PATCH_KNOWLEDGE for Blue Team (ingest separately)
    """
    collection = get_collection(collection_name)

    # TODO: batch insert into ChromaDB
    # collection.add(
    #     ids=[chunk["id"] for chunk in cve_chunks],
    #     documents=[chunk["document"] for chunk in cve_chunks],
    #     metadatas=[chunk["metadata"] for chunk in cve_chunks],
    # )
    # ChromaDB handles embedding via nomic-embed-text automatically

    raise NotImplementedError("ingest_to_chromadb() not yet implemented")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD CVE Scraper")
    parser.add_argument("--limit",    type=int,   default=100, help="Max CVEs to fetch")
    parser.add_argument("--min-cvss", type=float, default=9.0, help="Min CVSS score")
    args = parser.parse_args()

    cves   = fetch_cves(limit=args.limit, min_cvss=args.min_cvss)
    chunks = []
    for cve in cves:
        chunks.extend(chunk_cve_document(cve))

    ingest_to_chromadb(chunks, CVE_KNOWLEDGE)
    logger.info(f"[nvd] ✓ Loaded {len(cves)} CVE records ({len(chunks)} chunks) into {CVE_KNOWLEDGE}")