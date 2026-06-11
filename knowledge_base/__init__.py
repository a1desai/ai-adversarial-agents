"""Knowledge base ingestion pipeline.

Fetches CVE records from the NVD (nvd_scraper), chunks and embeds them
(chunker, embedder), and loads them into ChromaDB (run_ingestion) for the
Red/Blue Team agents to retrieve over. See issues #9-#12.
"""
