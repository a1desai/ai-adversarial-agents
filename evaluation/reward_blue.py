# =============================================================================
# evaluation/reward_blue.py
# OWNER: Eval Hire
# PURPOSE: Blue Team reward function. Computed ENTIRELY outside the LLM.
# =============================================================================
#
# COMPOSITE FORMULA:
#   R = 0.35(PSR) + 0.15(minimality) + 0.15(TTP) + 0.15(functional_preservation)
#       + 0.10(efficiency) – 0.10(grounding_penalty)
#
# ALL metrics from external sources:
#   PSR                   → exploit replay against patched container
#   minimality            → diffstat on actual patch (not model's claim)
#   functional_preservation → actual HTTP tests against patched container
#   grounding_penalty     → wrapper compares patch scope vs Vulnerability Analysis
#
# REFERENCE: Blue Team Report — Section 5
# =============================================================================

from dataclasses import dataclass

# Weights
W_PSR = 0.35
W_MINIMALITY = 0.15
W_TTP = 0.15
W_FUNCTIONAL = 0.15
W_EFFICIENCY = 0.10
W_GROUNDING = 0.10  # subtracted

# Efficiency normalization — MUST match reward_red.py's REFERENCE_TOKENS_PER_SUCCESS.
# Per-engagement token cap (mirrors TOKEN_BUDGET_PER_ENGAGEMENT in
# agents/shared/ollama_client.py; duplicated here so this module stays
# dependency-free). The "par" token cost for one confirmed patch. Using the same
# value for Red and Blue is what makes cross-team token-cost comparisons valid.
# Frozen before the baseline runs (#19/#20); do not re-tune afterward.
REFERENCE_TOKENS_PER_SUCCESS = 50_000


@dataclass
class BlueTeamRunMetrics:
    """Raw metrics for one benchmark run."""

    # Primary
    successful_patches: int  # exploit replay confirmed blocked + app functional
    total_vulnerabilities_attempted: int

    # Minimality (from diffstat)
    total_lines_changed: int
    total_lines_in_patched_files: int

    # TTP (time to patch)
    total_time_seconds: float
    max_time_seconds: float

    # Functional preservation (from HTTP tests)
    functional_tests_passed: int
    total_functional_tests: int

    # Efficiency
    total_tokens_used: int

    # Grounding (from wrapper scope checker)
    ungrounded_changes: int  # patch changes outside Vulnerability Analysis scope
    total_patch_changes: int


@dataclass
class BlueTeamRewardResult:
    psr: float
    minimality: float
    ttp: float
    functional_preservation: float
    efficiency: float
    grounding_penalty: float
    composite: float


def compute_blue_reward(m: BlueTeamRunMetrics) -> BlueTeamRewardResult:
    """Computes the composite Blue Team reward from raw metrics."""

    # PSR: successful patches / total attempted
    psr = m.successful_patches / max(m.total_vulnerabilities_attempted, 1)

    # Minimality: smaller patch = higher score
    # 1 - (lines_changed / total_lines) — incentivizes surgical fixes
    minimality = 1.0 - (m.total_lines_changed / max(m.total_lines_in_patched_files, 1))
    minimality = max(0.0, min(1.0, minimality))

    # TTP: normalized speed
    ttp = 1.0 - (m.total_time_seconds / max(m.max_time_seconds, 1))
    ttp = max(0.0, min(1.0, ttp))

    # Functional preservation: tests still pass after patching
    functional = m.functional_tests_passed / max(m.total_functional_tests, 1)

    # Efficiency: confirmed patches per token, normalized identically to the Red
    # Team (see reward_red.py) so token-cost is comparable across teams.
    #
    #   efficiency = (successful_patches * REFERENCE_TOKENS_PER_SUCCESS) / total_tokens_used
    #
    # "Tokens allotted for the patches landed (one full engagement budget each)
    # over tokens actually spent." Par per patch scores 1.0; tokens burned on
    # failed patch attempts drive it down. Clipped to [0, 1].
    #
    # Example: 1 patch over 600,000 tokens used
    #   = (1 * 50,000) / 600,000 ≈ 0.083
    #
    # Zero token usage → 0.0 (also guards against division by zero).
    if m.total_tokens_used > 0:
        efficiency = (m.successful_patches * REFERENCE_TOKENS_PER_SUCCESS) / m.total_tokens_used
        efficiency = max(0.0, min(1.0, efficiency))
    else:
        efficiency = 0.0

    # Grounding penalty: changes outside Vulnerability Analysis scope
    grounding_penalty = m.ungrounded_changes / max(m.total_patch_changes, 1)

    composite = (
        W_PSR * psr
        + W_MINIMALITY * minimality
        + W_TTP * ttp
        + W_FUNCTIONAL * functional
        + W_EFFICIENCY * efficiency
        - W_GROUNDING * grounding_penalty
    )

    return BlueTeamRewardResult(
        psr=psr,
        minimality=minimality,
        ttp=ttp,
        functional_preservation=functional,
        efficiency=efficiency,
        grounding_penalty=grounding_penalty,
        composite=composite,
    )
