# =============================================================================
# tests/unit/test_reward_functions.py
# OWNER: Eval Hire
# MARKERS: unit (pure math — no dependencies)
# PURPOSE: Tests for evaluation/reward_red.py and evaluation/reward_blue.py
# RUN: pytest tests/unit/test_reward_functions.py -v
# =============================================================================


from evaluation.reward_blue import (
    W_EFFICIENCY as BW_EFFICIENCY,
)
from evaluation.reward_blue import (
    W_FUNCTIONAL,
    W_MINIMALITY,
    W_PSR,
    W_TTP,
    BlueTeamRunMetrics,
    compute_blue_reward,
)
from evaluation.reward_red import (
    W_ADAPTATION,
    W_DIVERSITY,
    W_EFFICIENCY,
    W_ESR,
    W_TTE,
    RedTeamRunMetrics,
    compute_red_reward,
)

# ---------------------------------------------------------------------------
# Red Team Reward
# ---------------------------------------------------------------------------


class TestRedTeamReward:
    def _perfect_metrics(self) -> RedTeamRunMetrics:
        """A run where the agent did everything perfectly."""
        return RedTeamRunMetrics(
            successful_exploits=10,
            total_targets_attempted=10,
            total_time_seconds=100,
            max_time_seconds=900,
            unique_attack_types_achieved=8,
            total_tokens_used=5000,
            success_after_retry=2,
            total_retries=2,
            ungrounded_actions=0,
            total_actions=20,
        )

    def _zero_metrics(self) -> RedTeamRunMetrics:
        """A run where the agent achieved nothing."""
        return RedTeamRunMetrics(
            successful_exploits=0,
            total_targets_attempted=10,
            total_time_seconds=900,
            max_time_seconds=900,
            unique_attack_types_achieved=0,
            total_tokens_used=50000,
            success_after_retry=0,
            total_retries=5,
            ungrounded_actions=10,
            total_actions=10,
        )

    def test_weights_sum_correctly(self):
        """Weights must sum to 1.0 (grounding is subtracted, not added)."""
        positive_weights = W_ESR + W_TTE + W_DIVERSITY + W_EFFICIENCY + W_ADAPTATION
        assert abs(positive_weights - 1.0) < 0.01, (
            f"Weights sum to {positive_weights}, expected 1.0"
        )

    def test_perfect_run_has_high_composite(self):
        result = compute_red_reward(self._perfect_metrics())
        assert result.composite > 0.7

    def test_zero_run_has_low_composite(self):
        result = compute_red_reward(self._zero_metrics())
        assert result.composite < 0.2

    def test_esr_is_zero_when_no_successes(self):
        m = self._zero_metrics()
        result = compute_red_reward(m)
        assert result.esr == 0.0

    def test_esr_is_one_when_all_succeed(self):
        m = self._perfect_metrics()
        result = compute_red_reward(m)
        assert result.esr == 1.0

    def test_grounding_penalty_applied_when_ungrounded_actions(self):
        m = self._perfect_metrics()
        m.ungrounded_actions = 10
        m.total_actions = 10
        result = compute_red_reward(m)
        # Grounding penalty should reduce composite vs zero ungrounded
        m_clean = self._perfect_metrics()
        result_clean = compute_red_reward(m_clean)
        assert result.composite < result_clean.composite

    def test_no_division_by_zero_on_empty_run(self):
        m = RedTeamRunMetrics(
            successful_exploits=0,
            total_targets_attempted=0,
            total_time_seconds=0,
            max_time_seconds=900,
            unique_attack_types_achieved=0,
            total_tokens_used=0,
            success_after_retry=0,
            total_retries=0,
            ungrounded_actions=0,
            total_actions=0,
        )
        result = compute_red_reward(m)  # should not raise
        assert result is not None

    def test_composite_score_bounded(self):
        """Composite score should be between -0.1 and 1.0 in normal operation."""
        result = compute_red_reward(self._perfect_metrics())
        assert -0.15 <= result.composite <= 1.05


# ---------------------------------------------------------------------------
# Blue Team Reward
# ---------------------------------------------------------------------------


class TestBlueTeamReward:
    def _perfect_metrics(self) -> BlueTeamRunMetrics:
        return BlueTeamRunMetrics(
            successful_patches=5,
            total_vulnerabilities_attempted=5,
            total_lines_changed=10,
            total_lines_in_patched_files=500,
            total_time_seconds=200,
            max_time_seconds=900,
            functional_tests_passed=20,
            total_functional_tests=20,
            total_tokens_used=10000,
            ungrounded_changes=0,
            total_patch_changes=10,
        )

    def _zero_metrics(self) -> BlueTeamRunMetrics:
        return BlueTeamRunMetrics(
            successful_patches=0,
            total_vulnerabilities_attempted=5,
            total_lines_changed=100,
            total_lines_in_patched_files=200,
            total_time_seconds=900,
            max_time_seconds=900,
            functional_tests_passed=0,
            total_functional_tests=20,
            total_tokens_used=50000,
            ungrounded_changes=10,
            total_patch_changes=10,
        )

    def test_weights_sum_correctly(self):
        positive_weights = W_PSR + W_MINIMALITY + W_TTP + W_FUNCTIONAL + BW_EFFICIENCY
        assert abs(positive_weights - 1.0) < 0.01

    def test_perfect_run_has_high_composite(self):
        result = compute_blue_reward(self._perfect_metrics())
        assert result.composite > 0.6

    def test_zero_run_has_low_composite(self):
        result = compute_blue_reward(self._zero_metrics())
        assert result.composite < 0.2

    def test_minimal_patch_scores_higher_than_large_patch(self):
        m_small = self._perfect_metrics()
        m_small.total_lines_changed = 2

        m_large = self._perfect_metrics()
        m_large.total_lines_changed = 200

        result_small = compute_blue_reward(m_small)
        result_large = compute_blue_reward(m_large)
        assert result_small.minimality > result_large.minimality

    def test_grounding_penalty_reduces_score(self):
        m_clean = self._perfect_metrics()
        m_dirty = self._perfect_metrics()
        m_dirty.ungrounded_changes = 10
        m_dirty.total_patch_changes = 10

        result_clean = compute_blue_reward(m_clean)
        result_dirty = compute_blue_reward(m_dirty)
        assert result_clean.composite > result_dirty.composite

    def test_no_division_by_zero(self):
        m = BlueTeamRunMetrics(
            successful_patches=0,
            total_vulnerabilities_attempted=0,
            total_lines_changed=0,
            total_lines_in_patched_files=0,
            total_time_seconds=0,
            max_time_seconds=900,
            functional_tests_passed=0,
            total_functional_tests=0,
            total_tokens_used=0,
            ungrounded_changes=0,
            total_patch_changes=0,
        )
        result = compute_blue_reward(m)
        assert result is not None
