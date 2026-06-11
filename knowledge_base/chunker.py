# =============================================================================
# knowledge_base/chunker.py
# OWNER: Knowledge Base Hire
# PURPOSE: Split structured CVE records (from nvd_scraper.py) into retrievable
#          chunks for embedding into ChromaDB.
# =============================================================================
#
# CHUNKING STRATEGY (see knowledge_base/README.md):
#   - Prose (descriptions): 512-token windows, 50-token overlap.
#   - Code blocks / step-by-step procedures (exploit methodology, patch diffs):
#     preserved as ATOMIC units — never split mid-block.
#
# OUTPUT: chunk dicts shaped for ChromaDB:
#   {
#     "id":       deterministic string (cve_id + chunk_type [+ window index]),
#     "document": the text to embed,
#     "metadata": {cve_id, chunk_type, cwe_ids, primary_cwe, cvss_score, source},
#   }
#
# Deterministic ids matter: embedder.py upserts on them, so re-running the
# pipeline overwrites instead of duplicating (idempotency — issue #11).
#
# Note on tokens: we approximate a "token" as a whitespace-delimited word. This
# avoids a heavyweight tokenizer dependency and is close enough for windowing
# prose. nomic-embed-text truncates anything over its context window anyway.
# =============================================================================

from __future__ import annotations

CVE_CHUNK_TYPES = ("description", "technical", "reference")

PROSE_CHUNK_TOKENS = 512
PROSE_OVERLAP_TOKENS = 50


# ---------------------------------------------------------------------------
# Metadata helpers (ChromaDB metadata values must be str / int / float / bool)
# ---------------------------------------------------------------------------


def _base_metadata(cve: dict, chunk_type: str) -> dict:
    """Build the scalar-only metadata block shared by every chunk of a CVE."""
    cwe_ids = cve.get("cwe_ids") or []
    return {
        "cve_id": cve.get("cve_id", ""),
        "chunk_type": chunk_type,
        # Lists aren't valid ChromaDB metadata values — store as a CSV string.
        "cwe_ids": ",".join(cwe_ids),
        "primary_cwe": cwe_ids[0] if cwe_ids else "",
        "cvss_score": float(cve.get("cvss_score") or 0.0),
        "source": cve.get("source", "nvd"),
    }


def _window_prose(text: str, size: int, overlap: int) -> list[str]:
    """Split prose into overlapping token windows.

    Returns a single window when the text fits in ``size`` tokens (the common
    case for CVE descriptions), otherwise overlapping windows of ``size`` with
    ``overlap`` tokens shared between neighbours.
    """
    tokens = text.split()
    if len(tokens) <= size:
        return [text.strip()] if text.strip() else []

    step = max(1, size - overlap)
    windows: list[str] = []
    for start in range(0, len(tokens), step):
        window = tokens[start : start + size]
        if window:
            windows.append(" ".join(window))
        if start + size >= len(tokens):
            break
    return windows


# ---------------------------------------------------------------------------
# Chunk builders
# ---------------------------------------------------------------------------


def _description_chunks(cve: dict) -> list[dict]:
    """Prose chunk(s): the human description + affected technology + date."""
    parts = [cve.get("description", "").strip()]
    if cve.get("affected_technology"):
        parts.append(f"Affected: {cve['affected_technology']}")
    if cve.get("published_date"):
        parts.append(f"Published: {cve['published_date']}")
    text = "\n".join(p for p in parts if p)

    windows = _window_prose(text, PROSE_CHUNK_TOKENS, PROSE_OVERLAP_TOKENS)
    chunks = []
    multi = len(windows) > 1
    for i, window in enumerate(windows):
        meta = _base_metadata(cve, "description")
        chunk_id = f"{cve['cve_id']}::description"
        if multi:
            chunk_id = f"{chunk_id}::{i}"
            meta["window"] = i
        chunks.append({"id": chunk_id, "document": window, "metadata": meta})
    return chunks


def _technical_chunk(cve: dict) -> list[dict]:
    """Atomic chunk: CVSS + CWE classification + exploit methodology.

    Exploit methodology often contains payloads / step-by-step procedures, so
    this is kept whole — never windowed.
    """
    cwe_ids = cve.get("cwe_ids") or []
    lines = [
        f"CVE: {cve.get('cve_id', '')}",
        f"CVSS: {cve.get('cvss_score', '')} ({cve.get('cvss_vector', '')})",
        f"CWE: {', '.join(cwe_ids) if cwe_ids else 'unclassified'}",
    ]
    if cve.get("exploit_methodology"):
        lines.append("")
        lines.append("Exploit methodology:")
        lines.append(cve["exploit_methodology"])
    document = "\n".join(lines)
    return [
        {
            "id": f"{cve['cve_id']}::technical",
            "document": document,
            "metadata": _base_metadata(cve, "technical"),
        }
    ]


def _reference_chunk(cve: dict) -> list[dict]:
    """Atomic chunk: patch links, advisories, PoC references."""
    references = cve.get("references") or []
    body = "\n".join(f"- {url}" for url in references) if references else "(no references)"
    document = f"References for {cve.get('cve_id', '')}:\n{body}"
    meta = _base_metadata(cve, "reference")
    meta["reference_count"] = len(references)
    return [
        {
            "id": f"{cve['cve_id']}::reference",
            "document": document,
            "metadata": meta,
        }
    ]


def chunk_cve(cve: dict) -> list[dict]:
    """Split one CVE into its three knowledge chunks for ``cve_knowledge``.

    Returns description + technical + reference chunks (issue #10). The
    description chunk may expand into multiple overlapping windows for unusually
    long prose; technical and reference chunks are always atomic.
    """
    if not cve.get("cve_id"):
        raise ValueError("CVE record is missing 'cve_id'")
    return _description_chunks(cve) + _technical_chunk(cve) + _reference_chunk(cve)


def chunk_patch(cve: dict) -> list[dict]:
    """Build the patch-knowledge chunk for one CVE (for ``patch_knowledge``).

    The Blue Team's patch_knowledge collection needs remediation guidance, not
    exploit detail. This pulls the patch summary + the patch/advisory links into
    a single atomic chunk. Returns an empty list when there is no patch content
    to embed (so we never insert empty documents).
    """
    if not cve.get("cve_id"):
        raise ValueError("CVE record is missing 'cve_id'")

    patch_summary = (cve.get("patch_summary") or "").strip()
    references = cve.get("references") or []
    if not patch_summary and not references:
        return []

    cwe_ids = cve.get("cwe_ids") or []
    lines = [
        f"Patch guidance for {cve['cve_id']}" + (f" ({', '.join(cwe_ids)})" if cwe_ids else ""),
    ]
    if patch_summary:
        lines += ["", patch_summary]
    if references:
        lines += ["", "Patch / advisory links:"]
        lines += [f"- {url}" for url in references]

    meta = _base_metadata(cve, "patch")
    return [
        {
            "id": f"{cve['cve_id']}::patch",
            "document": "\n".join(lines),
            "metadata": meta,
        }
    ]
