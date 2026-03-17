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
W_PSR          = 0.35
W_MINIMALITY   = 0.15
W_TTP          = 0.15
W_FUNCTIONAL   = 0.15
W_EFFICIENCY   = 0.10
W_GROUNDING    = 0.10   # subtracted


@dataclass
class BlueTeamRunMetrics:
    """Raw metrics for one benchmark run."""

    # Primary
    successful_patches:        int    # exploit replay confirmed blocked + app functional
    total_vulnerabilities_attempted: int

    # Minimality (from diffstat)
    total_lines_changed:       int
    total_lines_in_patched_files: int

    # TTP (time to patch)
    total_time_seconds:        float
    max_time_seconds:          float

    # Functional preservation (from HTTP tests)
    functional_tests_passed:   int
    total_functional_tests:    int

    # Efficiency
    total_tokens_used:         int

    # Grounding (from wrapper scope checker)
    ungrounded_changes:        int    # patch changes outside Vulnerability Analysis scope
    total_patch_changes:       int


@dataclass
class BlueTeamRewardResult:
    psr:                  float
    minimality:           float
    ttp:                  float
    functional_preservation: float
    efficiency:           float
    grounding_penalty:    float
    composite:            float


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

    # Efficiency: TODO — define normalization
    efficiency = 0.0  # placeholder

    # Grounding penalty: changes outside Vulnerability Analysis scope
    grounding_penalty = m.ungrounded_changes / max(m.total_patch_changes, 1)

    composite = (
        W_PSR        * psr
        + W_MINIMALITY * minimality
        + W_TTP        * ttp
        + W_FUNCTIONAL * functional
        + W_EFFICIENCY * efficiency
        - W_GROUNDING  * grounding_penalty
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