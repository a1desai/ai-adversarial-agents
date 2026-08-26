# ADR-0002: ChromaDB as the local vector store

- **Status:** Accepted
- **Date:** 2026-08-25
- **Reference:** `docs/red_team_report.md` §3.4–3.5; `docs/blue_team_report.md` §3.4–3.5

<!-- NOTE: AI-assisted (drafted with Claude), human-reviewed. -->

## Context

The knowledge and memory architecture needs persistent vector storage with cosine
similarity search and metadata filtering (by CVE severity, CWE type, and target
technology). Like everything else in the project, it must be free, run locally on
student hardware with no separate managed service, and add no infrastructure cost.
The store must hold three distinct collections: a CVE knowledge collection, an
episodic-memory collection of prior exploit/defense attempts, and a procedural-memory
collection of validated playbooks.

## Decision

Use **ChromaDB** as the vector store. It is open-source, installs with a single
`pip install chromadb`, runs in-process (no separate server or container needed for
development), persists to local disk, and provides cosine similarity plus metadata
filtering out of the box. Embeddings come from `nomic-embed-text` (768-dim) served
via Ollama, with 512-token chunks and 50-token overlap for prose and full-block
preservation for code. Qdrant (also free, via Docker) is documented as an optional
upgrade path but is not used unless a specific ChromaDB limitation is hit.

## Consequences

- **Zero-ops:** running in-process inside the Python agent means no extra container
  in the deployment topology (see ADR-0007) and no service to operate.
- **Sufficient for scope:** persistence, metadata filtering, and cosine search cover
  every retrieval need the project has.
- **Scaling ceiling:** ChromaDB is not tuned for very large corpora or high-throughput
  gRPC access; if that becomes a bottleneck, the documented migration is to Qdrant.
- **Embedding lock-in:** the embedding model must remain consistent across all three
  collections, so changing it later requires re-embedding everything.
