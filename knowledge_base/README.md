# /knowledge_base — CVE Ingestion Pipeline

**OWNER: Knowledge Base Hire**  
**DEPENDS ON: agents/shared/memory.py (ChromaDB collections already initialized)**

---

## What Goes Here

The pipeline that fetches CVE data from NVD, processes it, and loads it into ChromaDB for agent retrieval.

---

## Data Sources (All Free)

| Source | What We Pull | How |
|---|---|---|
| NVD API | CVE descriptions, CVSS scores, CWE types, patch links | `nvdlib` Python library |
| GitHub | Official patch diffs linked from NVD advisories | GitHub REST API (no key needed for public repos) |
| OWASP | Secure Coding Practices, remediation guidance | Static download + chunking |
| CWE Top 25 | CWE-specific fix patterns | MITRE website scrape |

---

## ChromaDB Collections You Write To

Defined in `agents/shared/memory.py` — **do not redefine them here.**

| Collection | Who Reads It |
|---|---|
| `cve_knowledge` | Red Team Exploitation Agent |
| `patch_knowledge` | Blue Team Root Cause + Patch Generation Agents |

---

## Chunking Strategy

- **Prose documentation**: 512 tokens, 50-token overlap
- **Code blocks / diffs**: Preserve as atomic units — never split a code block
- **Step-by-step procedures**: Preserve as atomic units — never split a numbered list

---

## Folder Structure (Build This Out)

```
/knowledge_base/
├── README.md               ← This file
├── nvd_scraper.py          ← NVD API → raw CVE records
├── patch_scraper.py        ← GitHub patch diff extractor
├── chunker.py              ← Document chunking logic
├── embedder.py             ← nomic-embed-text → ChromaDB insertion
├── owasp_loader.py         ← OWASP + CWE static doc loader
└── run_ingestion.py        ← Master script: run all of the above in order
```

---

## Phase 1 Deliverable

`run_ingestion.py` should successfully load at least **100 CVE records** (CVSS >= 9.0, web application category) into ChromaDB before Phase 2 begins.

```bash
python knowledge_base/run_ingestion.py --limit 100 --min-cvss 9.0
# Expected: "Loaded 100 CVE records into cve_knowledge collection"
```