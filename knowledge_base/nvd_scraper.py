# =============================================================================
# knowledge_base/nvd_scraper.py
# OWNER: Knowledge Base Hire
# PURPOSE: Pulls CVE records from the NVD API and structures them for the
#          rest of the ingestion pipeline (chunker -> embedder).
# =============================================================================
#
# DATA SOURCE: NIST NVD API (free, no API key needed for basic access)
#   Docs: https://nvd.nist.gov/developers/vulnerabilities
#   Lib:  https://github.com/vehemont/nvdlib
#
# FILTERS:
#   - CVSS v3.x base score >= min_cvss (default 9.0 — critical severity)
#   - Web application vulnerability classes only (WEB_APP_CWES allowlist)
#
# SCOPE (issue #9): fetch and structure ONLY.
#   No chunking, no embedding, no ChromaDB here. fetch_cves() returns a list of
#   plain dicts matching the schema in dummy_data/cve_records/cve_records.json.
#   chunker.py (#10) and embedder.py (#11) consume that output downstream.
#
# CLI:
#   python knowledge_base/nvd_scraper.py --limit 100 --min-cvss 9.0
# =============================================================================

from __future__ import annotations

import argparse
import json

from loguru import logger

# nvdlib wraps the NVD API — free, no key needed.  pip install nvdlib
try:
    import nvdlib
except ImportError as err:  # pragma: no cover - import guard
    raise ImportError("Run: pip install nvdlib") from err


# ---------------------------------------------------------------------------
# Web-application CWE allowlist
# ---------------------------------------------------------------------------
# Only CVEs mapped to one of these weakness classes are kept. These are the
# vulnerability types our Red/Blue agents are expected to generalize over.
WEB_APP_CWES: dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-77": "Command Injection",
    "CWE-94": "Code Injection",
    "CWE-287": "Improper Authentication",
    "CWE-285": "Improper Authorization",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-98": "PHP Remote File Inclusion",
}

# NVD rate limit without an API key is ~5 requests / 30s. nvdlib sleeps this
# many seconds between its own paged requests; without an API key it requires
# delay >= 6s. Passing it through searchCVE(delay=...) is how we "sleep between
# requests" to avoid 403/429 throttling.
RATE_LIMIT_DELAY_S = 6.0


def _extract_cwe_ids(raw) -> list[str]:
    """Pull the CWE identifiers out of an nvdlib CVE object.

    nvdlib exposes weaknesses on ``raw.cwe`` as a list of objects each with a
    ``.value`` like ``"CWE-89"``. Some entries are noise (``NVD-CWE-noinfo``,
    ``NVD-CWE-Other``) — those never match the allowlist and get filtered out.
    """
    cwes: list[str] = []
    for weakness in getattr(raw, "cwe", None) or []:
        value = getattr(weakness, "value", None)
        if value and value.startswith("CWE-"):
            cwes.append(value)
    return cwes


def _extract_cvss(raw) -> tuple[float | None, str]:
    """Return (score, vector) preferring CVSS v3.1, then v3.0, then v2."""
    for score_attr, vector_attr in (
        ("v31score", "v31vector"),
        ("v30score", "v30vector"),
        ("v2score", "v2vector"),
    ):
        score = getattr(raw, score_attr, None)
        if score:
            return float(score), getattr(raw, vector_attr, "") or ""
    return None, ""


def _english_description(raw) -> str:
    """Return the English description, falling back to the first available."""
    descriptions = getattr(raw, "descriptions", None) or []
    for desc in descriptions:
        if getattr(desc, "lang", None) == "en":
            return desc.value
    return descriptions[0].value if descriptions else ""


def normalize_cve(raw) -> dict:
    """Map a raw nvdlib CVE object onto our canonical CVE dict schema.

    Pure function — kept separate from the network call so it can be unit
    tested with a stub object. Mirrors the schema in
    dummy_data/cve_records/cve_records.json. Fields the NVD does not provide
    (``exploit_methodology``, ``patch_summary``, ``affected_technology``) are
    left empty here and enriched later by patch_scraper.py / owasp_loader.py.
    """
    score, vector = _extract_cvss(raw)
    references = [
        getattr(ref, "url", None)
        for ref in (getattr(raw, "references", None) or [])
        if getattr(ref, "url", None)
    ]
    return {
        "cve_id": getattr(raw, "id", ""),
        "description": _english_description(raw),
        "cvss_score": score,
        "cvss_vector": vector,
        "cwe_ids": _extract_cwe_ids(raw),
        "affected_technology": "",  # enriched later (NVD CPE parsing is noisy)
        "published_date": getattr(raw, "published", "") or "",
        "exploit_methodology": "",  # enriched later by patch_scraper / PoC links
        "patch_summary": "",  # enriched later from GitHub patch diffs / OWASP
        "references": references,
    }


def _is_web_app_cve(cve: dict) -> bool:
    """True if any of the CVE's CWE ids is in the web-app allowlist."""
    return any(cwe in WEB_APP_CWES for cwe in cve["cwe_ids"])


def fetch_cves(
    limit: int = 100,
    min_cvss: float = 9.0,
    *,
    api_key: str | None = None,
    delay: float = RATE_LIMIT_DELAY_S,
    _searcher=None,
) -> list[dict]:
    """Fetch and structure critical web-application CVEs from the NVD.

    Args:
        limit:    maximum number of structured CVE dicts to return.
        min_cvss: minimum CVSS base score (NVD ``CRITICAL`` is >= 9.0).
        api_key:  optional NVD API key. Without one, nvdlib auto-applies a 6s
                  delay between requests; ``delay`` is only forwarded with a key
                  (nvdlib rejects an explicit delay otherwise).
        delay:    seconds between requests when an ``api_key`` is supplied.
        _searcher: injection seam for tests — defaults to ``nvdlib.searchCVE``.

    Returns:
        List of CVE dicts (see ``normalize_cve``), de-duplicated by ``cve_id``,
        each passing the web-app CWE allowlist and the ``min_cvss`` threshold.
    """
    searcher = _searcher or nvdlib.searchCVE
    logger.info(f"[nvd] Fetching CVEs: limit={limit} min_cvss={min_cvss}")

    # Only pass key/delay together — nvdlib raises if delay is given without a
    # key, and applies its safe 6s default delay automatically when key-less.
    rate_kwargs = {"key": api_key, "delay": delay} if api_key else {}

    collected: dict[str, dict] = {}

    # Query NVD once per allowlisted CWE using server-side filtering
    # (severity + cweId), accumulating across classes until we hit the limit.
    # nvdlib paginates and rate-limits internally per request.
    for cwe in WEB_APP_CWES:
        if len(collected) >= limit:
            break

        logger.debug(f"[nvd] Querying CRITICAL CVEs for {cwe} ...")
        results = searcher(
            cvssV3Severity="CRITICAL",
            cweId=cwe,
            limit=limit,
            **rate_kwargs,
        )

        for raw in results or []:
            cve = normalize_cve(raw)
            if cve["cvss_score"] is None or cve["cvss_score"] < min_cvss:
                continue
            if not _is_web_app_cve(cve):
                continue
            collected[cve["cve_id"]] = cve  # dedupe by id across CWE classes
            if len(collected) >= limit:
                break

    cves = list(collected.values())[:limit]
    logger.info(f"[nvd] ✓ Structured {len(cves)} web-app CVEs (CVSS >= {min_cvss})")
    return cves


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD CVE scraper (fetch + structure only)")
    parser.add_argument("--limit", type=int, default=100, help="Max CVEs to fetch")
    parser.add_argument("--min-cvss", type=float, default=9.0, help="Min CVSS base score")
    parser.add_argument("--out", type=str, default="", help="Optional path to write JSON")
    args = parser.parse_args()

    cves = fetch_cves(limit=args.limit, min_cvss=args.min_cvss)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(cves, f, indent=2)
        logger.info(f"[nvd] Wrote {len(cves)} CVEs to {args.out}")
    else:
        print(json.dumps(cves, indent=2))
