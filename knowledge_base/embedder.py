# =============================================================================
# knowledge_base/embedder.py
# OWNER: Knowledge Base Hire
# PURPOSE: Insert chunked CVE data (from chunker.py) into ChromaDB collections.
# =============================================================================
#
# Embeddings are produced by the shared nomic-embed-text function wired into
# every collection in agents/shared/memory.py — we never embed by hand here,
# ChromaDB calls the embedding function on insert.
#
# IDEMPOTENCY (issue #11): inserts use ``collection.upsert`` keyed on the
# deterministic chunk ids from chunker.py. Re-running the pipeline overwrites
# existing chunks in place instead of creating duplicates.
#
# COLLECTIONS:
#   cve_knowledge   <- chunk_cve()   output  (Red Team)
#   patch_knowledge <- chunk_patch() output  (Blue Team)
# =============================================================================

from __future__ import annotations

from loguru import logger

from agents.shared.memory import (
    CVE_KNOWLEDGE,
    PATCH_KNOWLEDGE,
    get_collection,
)

# ChromaDB rejects oversized single requests; insert in batches.
_BATCH_SIZE = 100


def _validate_chunks(chunks: list[dict]) -> None:
    for chunk in chunks:
        missing = {"id", "document", "metadata"} - chunk.keys()
        if missing:
            raise ValueError(f"Chunk missing required keys {missing}: {chunk!r}")


def embed_chunks(
    chunks: list[dict],
    collection_name: str = CVE_KNOWLEDGE,
    *,
    collection=None,
) -> int:
    """Upsert chunk dicts into a ChromaDB collection.

    Args:
        chunks:          output of chunker.chunk_cve / chunk_patch.
        collection_name: target collection (CVE_KNOWLEDGE or PATCH_KNOWLEDGE).
        collection:      injection seam for tests — pass an ephemeral
                         collection to avoid touching the on-disk DB / Ollama.

    Returns:
        Number of chunks upserted.

    Idempotent: re-running with the same chunks overwrites by id rather than
    duplicating.
    """
    if not chunks:
        logger.info(f"[embed] No chunks to insert into '{collection_name}' — skipping.")
        return 0

    _validate_chunks(chunks)
    col = collection if collection is not None else get_collection(collection_name)

    for start in range(0, len(chunks), _BATCH_SIZE):
        batch = chunks[start : start + _BATCH_SIZE]
        col.upsert(
            ids=[c["id"] for c in batch],
            documents=[c["document"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )

    logger.info(f"[embed] ✓ Upserted {len(chunks)} chunks into '{collection_name}'")
    return len(chunks)


def embed_cve_chunks(chunks: list[dict], *, collection=None) -> int:
    """Convenience wrapper: insert CVE-knowledge chunks into ``cve_knowledge``."""
    return embed_chunks(chunks, CVE_KNOWLEDGE, collection=collection)


def embed_patch_chunks(chunks: list[dict], *, collection=None) -> int:
    """Convenience wrapper: insert patch chunks into ``patch_knowledge``."""
    return embed_chunks(chunks, PATCH_KNOWLEDGE, collection=collection)
