# =============================================================================
# agents/shared/ollama_client.py
# OWNER: Lead — DO NOT MODIFY temperature/model settings without lead approval
# DEPENDS ON: ollama (running locally on port 11434)
# PURPOSE: Centralized Ollama wrapper with role-specific configurations.
#          All agents call this — never instantiate ollama.Client directly.
# =============================================================================
#
# MODEL ROLES:
#   REASONING  → llama3.1:8b-instruct-q4_K_M
#                Used by: Red Supervisor, Recon Agent, Exploitation Agent (planning)
#                         Blue Supervisor, Log Analysis Agent, Root Cause Agent
#
#   CODE_GEN   → qwen2.5-coder:7b-instruct-q4_K_M
#                Used by: Red Exploitation Agent (payload generation)
#                         Blue Patch Generation Agent
#                Fallback: REASONING model if VRAM is constrained
#
# TEMPERATURE GUIDE (locked — do not override without justification in PR):
#   Patch generation:        0.1  (correctness is paramount — bad patch = broken app)
#   Exploit code generation: 0.2  (precision matters)
#   Log analysis / recon:    0.4  (some interpretive flexibility useful)
#   Attack planning:         0.6  (creative lateral thinking about attack vectors)
# =============================================================================

from dataclasses import dataclass
from enum import StrEnum

import ollama
from loguru import logger

# ---------------------------------------------------------------------------
# Model Roles
# ---------------------------------------------------------------------------


class ModelRole(StrEnum):
    REASONING = "reasoning"  # strategic planning, log analysis, root cause
    CODE_GEN = "code_gen"  # exploit payloads, patch code


# Model strings — change here only, never hardcode in agent files
MODEL_MAP = {
    ModelRole.REASONING: "llama3.1:8b-instruct-q4_K_M",
    ModelRole.CODE_GEN: "qwen2.5-coder:7b-instruct-q4_K_M",
}

# Fallback: if VRAM is too constrained to load CODE_GEN, use REASONING for everything
FALLBACK_TO_REASONING = False  # set True in .env on constrained machines


# ---------------------------------------------------------------------------
# Temperature Presets (per task type — do not change without PR + justification)
# ---------------------------------------------------------------------------


class TaskType(StrEnum):
    PATCH_GENERATION = "patch_generation"  # 0.1 — correctness critical
    EXPLOIT_CODE = "exploit_code"  # 0.2 — precision matters
    ROOT_CAUSE = "root_cause"  # 0.3 — analytical
    LOG_ANALYSIS = "log_analysis"  # 0.4 — interpretive
    RECON_ANALYSIS = "recon_analysis"  # 0.4 — interpretive
    ATTACK_PLANNING = "attack_planning"  # 0.6 — creative lateral thinking
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"  # 0.3 — analytical


TEMPERATURE_MAP = {
    TaskType.PATCH_GENERATION: 0.1,
    TaskType.EXPLOIT_CODE: 0.2,
    TaskType.ROOT_CAUSE: 0.3,
    TaskType.VULNERABILITY_ANALYSIS: 0.3,
    TaskType.LOG_ANALYSIS: 0.4,
    TaskType.RECON_ANALYSIS: 0.4,
    TaskType.ATTACK_PLANNING: 0.6,
}

# Fixed params — same for all tasks
TOP_P = 0.9
REPEAT_PENALTY = 1.1
MAX_TOKENS = 2048  # per completion — Supervisor enforces 50K total per engagement
NUM_CTX = 8192  # context window — 4096 default overflows with episodic memory growth


# ---------------------------------------------------------------------------
# Token Budget Tracking
# ---------------------------------------------------------------------------


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            self.prompt_tokens + other.prompt_tokens,
            self.completion_tokens + other.completion_tokens,
        )


# Per-engagement budget cap (enforced by Supervisor, tracked here)
TOKEN_BUDGET_PER_ENGAGEMENT = 50_000


# ---------------------------------------------------------------------------
# Core Client
# ---------------------------------------------------------------------------


class OllamaClient:
    """
    Centralized Ollama client for all agents.

    Usage:
        client = OllamaClient()
        response, usage = client.chat(
            role=ModelRole.REASONING,
            task=TaskType.LOG_ANALYSIS,
            messages=[{"role": "user", "content": "Analyze this log..."}],
        )
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        self._client = ollama.Client(host=base_url)
        self._cumulative_usage = TokenUsage()
        logger.info("[ollama] Client initialized")

    def _resolve_model(self, role: ModelRole) -> str:
        if FALLBACK_TO_REASONING:
            return MODEL_MAP[ModelRole.REASONING]
        return MODEL_MAP[role]

    def chat(
        self,
        role: ModelRole,
        task: TaskType,
        messages: list[dict],
        system_prompt: str | None = None,
    ) -> tuple[str, TokenUsage]:
        """
        Sends a chat completion request to Ollama.

        Args:
            role:          which model to use (REASONING or CODE_GEN)
            task:          task type — determines temperature
            messages:      list of {"role": ..., "content": ...} dicts
            system_prompt: optional system message prepended to messages

        Returns:
            (response_text, token_usage)

        Raises:
            RuntimeError if Ollama is unreachable or model not found
        """
        model = self._resolve_model(role)
        temperature = TEMPERATURE_MAP[task]

        # Prepend system prompt if provided
        full_messages = []
        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})
        full_messages.extend(messages)

        logger.debug(
            f"[ollama] model={model} task={task} temp={temperature} msgs={len(full_messages)}"
        )

        try:
            response = self._client.chat(
                model=model,
                messages=full_messages,
                options={
                    "temperature": temperature,
                    "top_p": TOP_P,
                    "repeat_penalty": REPEAT_PENALTY,
                    "num_predict": MAX_TOKENS,
                    "num_ctx": NUM_CTX,
                },
            )
        except Exception as e:
            logger.error(f"[ollama] Request failed: {e}")
            raise RuntimeError(f"Ollama request failed for model={model}: {e}") from e

        content = response.message.content

        # Track token usage
        usage = TokenUsage(
            prompt_tokens=getattr(response, "prompt_eval_count", None) or 0,
            completion_tokens=getattr(response, "eval_count", None) or 0,
        )
        self._cumulative_usage = self._cumulative_usage + usage

        logger.debug(
            f"[ollama] ✓ {usage.prompt_tokens}p + {usage.completion_tokens}c = {usage.total} tokens "
            f"(cumulative: {self._cumulative_usage.total}/{TOKEN_BUDGET_PER_ENGAGEMENT})"
        )

        # Warn if approaching budget
        if self._cumulative_usage.total > TOKEN_BUDGET_PER_ENGAGEMENT * 0.8:
            logger.warning(
                f"[ollama] ⚠ Approaching token budget: "
                f"{self._cumulative_usage.total}/{TOKEN_BUDGET_PER_ENGAGEMENT}"
            )

        return content, usage

    @property
    def cumulative_usage(self) -> TokenUsage:
        return self._cumulative_usage

    def reset_usage(self):
        """Call at the start of each engagement to reset the token ledger."""
        self._cumulative_usage = TokenUsage()
        logger.debug("[ollama] Token usage reset for new engagement")

    def is_over_budget(self) -> bool:
        return self._cumulative_usage.total >= TOKEN_BUDGET_PER_ENGAGEMENT

    def verify_models_available(self) -> bool:
        """
        Checks that required models are pulled and available in Ollama.
        Call this at startup before running any agents.
        """
        try:
            available = {m.model for m in self._client.list().models}
        except Exception as e:
            logger.error(f"[ollama] Cannot connect to Ollama: {e}")
            return False

        required = set(MODEL_MAP.values())
        missing = required - available

        if missing:
            logger.error(f"[ollama] Missing models: {missing}")
            logger.error("[ollama] Run: ollama pull <model-name>")
            return False

        logger.info(f"[ollama] ✓ All required models available: {required}")
        return True


# ---------------------------------------------------------------------------
# Singleton — agents import this, don't instantiate their own
# ---------------------------------------------------------------------------

_client_instance: OllamaClient | None = None


def get_client() -> OllamaClient:
    """Returns the shared OllamaClient singleton."""
    global _client_instance
    if _client_instance is None:
        _client_instance = OllamaClient()
    return _client_instance


# ---------------------------------------------------------------------------
# Entry point: run this directly to verify Ollama is reachable
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    client = get_client()
    ok = client.verify_models_available()
    if ok:
        print("\n✓ Ollama is running and all models are available.")
        # Quick smoke test
        response, usage = client.chat(
            role=ModelRole.REASONING,
            task=TaskType.LOG_ANALYSIS,
            messages=[{"role": "user", "content": "Reply with only: OK"}],
        )
        print(f"  Smoke test response: {response.strip()}")
        print(f"  Tokens used: {usage.total}")
    else:
        print("\n✗ Ollama setup incomplete. See errors above.")
