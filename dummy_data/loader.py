# =============================================================================
# dummy_data/loader.py
# PURPOSE: Utility to load dummy data into ChromaDB for local development.
#          Run this on a fresh machine to populate ChromaDB without hitting NVD.
# USAGE:   python dummy_data/loader.py
# =============================================================================

import json
import sys
from pathlib import Path
from loguru import logger

DUMMY_DATA = Path(__file__).parent


def load_cve_records_into_chromadb():
    """
    Loads the 5 dummy CVE records into both cve_knowledge and patch_knowledge
    collections. Use this for local dev when you don't want to hit the NVD API.
    """
    from agents.shared.memory import get_collection, CVE_KNOWLEDGE, PATCH_KNOWLEDGE

    with open(DUMMY_DATA / "cve_records" / "cve_records.json") as f:
        records = json.load(f)

    for collection_name in [CVE_KNOWLEDGE, PATCH_KNOWLEDGE]:
        col = get_collection(collection_name)

        # Skip if already loaded
        existing_ids = set()
        try:
            existing = col.get(ids=[r["cve_id"] for r in records])
            existing_ids = set(existing["ids"])
        except Exception:
            pass

        new_records = [r for r in records if r["cve_id"] not in existing_ids]
        if not new_records:
            logger.info(f"[loader] {collection_name}: all records already loaded, skipping")
            continue

        col.add(
            ids=[r["cve_id"] for r in new_records],
            documents=[
                f"{r['description']} Exploit methodology: {r['exploit_methodology']} "
                f"Patch: {r['patch_summary']}"
                for r in new_records
            ],
            metadatas=[{
                "cve_id":              r["cve_id"],
                "cvss_score":          r["cvss_score"],
                "cwe_ids":             ",".join(r["cwe_ids"]),
                "affected_technology": r["affected_technology"],
                "published_date":      r["published_date"],
            } for r in new_records],
        )
        logger.info(f"[loader] {collection_name}: loaded {len(new_records)} dummy CVE records")


if __name__ == "__main__":
    logger.info("[loader] Loading dummy data into ChromaDB...")
    load_cve_records_into_chromadb()
    logger.info("[loader] ✓ Done. ChromaDB is ready for local development.")
    logger.info("[loader]   Run 'python agents/shared/memory.py' to verify.")