# =============================================================================
# tests/conftest.py
# PURPOSE: Shared pytest fixtures available to ALL tests under tests/.
#          Mocks Ollama and ChromaDB so unit tests run without any services.
# =============================================================================

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# tests/conftest.py → repo root = parent.parent
DUMMY_DATA = Path(__file__).parent.parent / "dummy_data"


# ---------------------------------------------------------------------------
# Dummy Data Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dummy_cve_records():
    """Returns the 5 fake CVE records from dummy_data/."""
    path = DUMMY_DATA / "cve_records" / "cve_records.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def dummy_sqli_log():
    """Returns the SQL injection exploit log as a string."""
    path = DUMMY_DATA / "exploit_logs" / "sqli_exploit.log"
    return path.read_text()


@pytest.fixture
def dummy_rce_log():
    """Returns the RCE file upload exploit log as a string."""
    path = DUMMY_DATA / "exploit_logs" / "rce_file_upload.log"
    return path.read_text()


@pytest.fixture
def dummy_payloads():
    """Returns the attack payloads dict from dummy_data/."""
    path = DUMMY_DATA / "attack_payloads" / "payloads.json"
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Mock Ollama (unit tests don't need a real GPU)
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ollama_response():
    """
    Returns a factory for fake Ollama chat responses (new SDK Pydantic format).
    Usage: mock_ollama_response("some response text")
    """

    def _factory(content: str = "OK", prompt_tokens: int = 100, completion_tokens: int = 50):
        resp = MagicMock()
        resp.message.content = content
        resp.prompt_eval_count = prompt_tokens
        resp.eval_count = completion_tokens
        return resp

    return _factory


@pytest.fixture
def mock_ollama_client(mock_ollama_response):
    """
    Patches the Ollama client so no real inference happens.
    Inject this into any test that calls ollama_client.chat().
    """
    with patch("agents.shared.ollama_client.ollama.Client") as mock_cls:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = mock_ollama_response("OK")
        mock_instance.list.return_value = MagicMock(
            models=[
                MagicMock(model="llama3.1:8b-instruct-q4_K_M"),
                MagicMock(model="qwen2.5-coder:7b-instruct-q4_K_M"),
                MagicMock(model="nomic-embed-text"),
            ]
        )
        mock_cls.return_value = mock_instance
        yield mock_instance


# ---------------------------------------------------------------------------
# In-Memory ChromaDB (unit tests use ephemeral DB, not disk)
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_chroma():
    """
    Returns a fresh in-memory ChromaDB client for each test.
    Isolated — no data persists between tests.
    """
    import chromadb

    return chromadb.EphemeralClient()


@pytest.fixture
def mock_embedding_function():
    """
    Returns a fake embedding function that produces deterministic vectors.
    Avoids needing nomic-embed-text running during unit tests.

    Implements the chromadb >= 0.5 EmbeddingFunction interface:
    __call__, name(), and is_legacy (used by ChromaDB's collection-config
    conflict checker).
    """

    class FakeEmbeddingFunction:
        is_legacy = False

        def _embed(self, texts: list[str]) -> list[list[float]]:
            # Deterministic fake embeddings based on string length
            return [[float(len(s) % 10) / 10.0] * 768 for s in texts]

        # ChromaDB ≥ 0.5 calls embed_query / embed_documents on the new API path.
        # Legacy code still calls __call__.
        def __call__(self, input: list[str]) -> list[list[float]]:
            return self._embed(input)

        def embed_query(self, input: list[str]) -> list[list[float]]:
            return self._embed(input)

        def embed_documents(self, input: list[str]) -> list[list[float]]:
            return self._embed(input)

        def name(self) -> str:
            return "fake-embedding-function"

    return FakeEmbeddingFunction()
