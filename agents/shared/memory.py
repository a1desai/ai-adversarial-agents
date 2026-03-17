# =============================================================================
# agents/shared/memory.py
# OWNER: Lead — DO NOT MODIFY schema without lead approval
# DEPENDS ON: chromadb, ollama (nomic-embed-text)
# PURPOSE: Initializes and provides access to all 5 ChromaDB collections
#          used across Red Team and Blue Team agents.
# =============================================================================
#
# COLLECTIONS:
#   RED TEAM:
#     1. cve_knowledge       — CVE descriptions, exploit procedures, MITRE ATT&CK
#     2. red_episodic        — Records of individual exploit attempts (success/fail)
#     3. red_procedural      — Validated, reusable attack playbooks
#
#   BLUE TEAM:
#     4. patch_knowledge     — CVE patch diffs, OWASP remediation, CWE fix patterns
#     5. blue_episodic       — Records of patching attempts (success/fail/regression)
#     6. blue_procedural     — Validated patching playbooks per CWE type
#
# RETRIEVAL PRIORITY (both teams):
#   procedural > episodic > semantic (knowledge)
#
# CONTEXT BUDGET:
#   30% memory retrieval | 30% current recon/evidence | 40% reasoning
# =============================================================================

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from loguru import logger
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent.parent.parent / ".chromadb"  # repo root/.chromadb
EMBEDDING_MODEL = "nomic-embed-text"  # served via Ollama — DO NOT CHANGE
OLLAMA_BASE_URL = "http://localhost:11434"

# Collection names — treat as constants, never hardcode strings elsewhere
CVE_KNOWLEDGE      = "cve_knowledge"
RED_EPISODIC       = "red_episodic"
RED_PROCEDURAL     = "red_procedural"
PATCH_KNOWLEDGE    = "patch_knowledge"
BLUE_EPISODIC      = "blue_episodic"
BLUE_PROCEDURAL    = "blue_procedural"

ALL_COLLECTIONS = [
    CVE_KNOWLEDGE,
    RED_EPISODIC,
    RED_PROCEDURAL,
    PATCH_KNOWLEDGE,
    BLUE_EPISODIC,
    BLUE_PROCEDURAL,
]


# ---------------------------------------------------------------------------
# Embedding Function (nomic-embed-text via Ollama)
# ---------------------------------------------------------------------------

def get_embedding_function():
    """
    Returns the nomic-embed-text embedding function served through Ollama.
    Must be consistent across ALL collections — never mix embedding models.
    """
    return embedding_functions.OllamaEmbeddingFunction(
        url=f"{OLLAMA_BASE_URL}/api/embeddings",
        model_name=EMBEDDING_MODEL,
    )


# ---------------------------------------------------------------------------
# Client Initialization
# ---------------------------------------------------------------------------

def get_client() -> chromadb.PersistentClient:
    """
    Returns a persistent ChromaDB client stored at DB_PATH.
    Data survives restarts — no server process needed.
    """
    DB_PATH.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(
        path=str(DB_PATH),
        settings=Settings(anonymized_telemetry=False),
    )


# ---------------------------------------------------------------------------
# Collection Accessors
# ---------------------------------------------------------------------------

def get_collection(name: str) -> chromadb.Collection:
    """
    Returns a collection by name. Creates it if it doesn't exist.
    Always uses the shared embedding function.
    """
    if name not in ALL_COLLECTIONS:
        raise ValueError(f"Unknown collection '{name}'. Must be one of: {ALL_COLLECTIONS}")

    client = get_client()
    ef = get_embedding_function()

    collection = client.get_or_create_collection(
        name=name,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},  # cosine similarity for all collections
    )
    logger.debug(f"[memory] Accessed collection '{name}' ({collection.count()} docs)")
    return collection


# ---------------------------------------------------------------------------
# Initialization (run once at startup)
# ---------------------------------------------------------------------------

def initialize_all_collections() -> dict[str, chromadb.Collection]:
    """
    Creates all 6 collections if they don't exist.
    Safe to call multiple times — idempotent.
    Returns a dict of collection_name → Collection.
    """
    logger.info("[memory] Initializing all ChromaDB collections...")
    collections = {}
    for name in ALL_COLLECTIONS:
        collections[name] = get_collection(name)
        logger.info(f"[memory]   ✓ {name} ({collections[name].count()} docs)")
    logger.info("[memory] All collections ready.")
    return collections


# ---------------------------------------------------------------------------
# Schema Reference (for hires — do not change without lead approval)
# ---------------------------------------------------------------------------
#
# RED EPISODIC MEMORY — schema for each record:
# {
#   "episode_id":          UUID string
#   "target_cve":          e.g. "CVE-2024-1234"
#   "target_technology":   e.g. "WordPress 6.4"
#   "technique_attempted": e.g. "SQL injection via UNION-based extraction"
#   "payload":             exact payload or command sequence
#   "response_summary":    summarized server response
#   "outcome":             "SUCCESS" | "FAILURE" | "PARTIAL"
#   "failure_reason":      why it failed (null on success)
#   "timestamp":           ISO 8601
# }
# Embedding vector: concatenation of technique_attempted + response_summary
#
# BLUE EPISODIC MEMORY — schema for each record:
# {
#   "episode_id":          UUID string
#   "target_cve":          e.g. "CVE-2024-1234"
#   "target_technology":   e.g. "WordPress 6.4"
#   "attack_summary":      how the Red Team exploited the vulnerability
#   "cwe_classification":  e.g. "CWE-89: SQL Injection"
#   "patch_strategy":      e.g. "Replace string concatenation with prepared statements"
#   "patch_diff":          the actual unified diff of the attempted patch
#   "outcome":             "SUCCESS" | "FAILURE" | "REGRESSION"
#   "failure_reason":      why it failed (null on success)
#   "timestamp":           ISO 8601
# }
# Embedding vector: concatenation of cwe_classification + patch_strategy + failure_reason
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Retrieval Helpers
# ---------------------------------------------------------------------------

def query_collection(
    collection_name: str,
    query_text: str,
    n_results: int = 5,
    where: dict | None = None,
) -> list[dict]:
    """
    Semantic similarity search against a collection.

    Args:
        collection_name: one of ALL_COLLECTIONS
        query_text:      natural language query
        n_results:       how many results to return (keep low — token budget matters)
        where:           optional ChromaDB metadata filter
                         e.g. {"cwe_type": "CWE-89"} or {"outcome": "SUCCESS"}

    Returns:
        List of dicts with keys: id, document, metadata, distance
    """
    collection = get_collection(collection_name)

    kwargs = {
        "query_texts": [query_text],
        "n_results": min(n_results, collection.count()) if collection.count() > 0 else 1,
        "include": ["documents", "metadatas", "distances"],
    }
    if where:
        kwargs["where"] = where

    results = collection.query(**kwargs)

    formatted = []
    for i in range(len(results["ids"][0])):
        formatted.append({
            "id":       results["ids"][0][i],
            "document": results["documents"][0][i],
            "metadata": results["metadatas"][0][i],
            "distance": results["distances"][0][i],
        })

    return formatted


def parallel_retrieval(
    query_text: str,
    team: str,  # "red" or "blue"
    n_results_each: int = 3,
    metadata_filter: dict | None = None,
) -> dict[str, list[dict]]:
    """
    Performs three parallel retrievals (procedural > episodic > semantic)
    for the given team. Returns merged results keyed by memory type.

    Priority order: procedural > episodic > knowledge
    Use this in agent context assembly — not raw query_collection calls.

    Args:
        query_text:       what the agent is looking for
        team:             "red" or "blue"
        n_results_each:   results per collection (keep low: 3 is usually enough)
        metadata_filter:  optional filter applied to all three collections

    Returns:
        {
            "procedural": [...],   # highest priority
            "episodic":   [...],
            "knowledge":  [...],   # lowest priority
        }
    """
    if team not in ("red", "blue"):
        raise ValueError("team must be 'red' or 'blue'")

    if team == "red":
        procedural_col = RED_PROCEDURAL
        episodic_col   = RED_EPISODIC
        knowledge_col  = CVE_KNOWLEDGE
    else:
        procedural_col = BLUE_PROCEDURAL
        episodic_col   = BLUE_EPISODIC
        knowledge_col  = PATCH_KNOWLEDGE

    return {
        "procedural": query_collection(procedural_col, query_text, n_results_each, metadata_filter),
        "episodic":   query_collection(episodic_col,   query_text, n_results_each, metadata_filter),
        "knowledge":  query_collection(knowledge_col,  query_text, n_results_each, metadata_filter),
    }


# ---------------------------------------------------------------------------
# Entry point: run this directly to verify setup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    collections = initialize_all_collections()
    print("\n✓ ChromaDB initialized successfully.")
    print(f"  Storage path: {DB_PATH}")
    for name, col in collections.items():
        print(f"  {name}: {col.count()} documents")