"""Tests for BehavioralTrustScorer — E15.3."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_identity.behavioral_trust.scorer import (
    BehaviorEvent,
    BehavioralTrustScore,
    BehavioralTrustScorer,
    EventType,
    ScorerConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc(offset_hours: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=offset_hours)


def _make_scorer(
    initial_score: float = 50.0,
    completion_delta: float = 2.0,
    failure_delta: float = -3.0,
    violation_delta: float = -10.0,
) -> BehavioralTrustScorer:
    config = ScorerConfig(
        initial_score=initial_score,
        completion_delta=completion_delta,
        failure_delta=failure_delta,
        violation_delta=violation_delta,
        decay_per_hour=0.0,  # Disable time decay in most tests
    )
    return BehavioralTrustScorer(config)


# ---------------------------------------------------------------------------
# ScorerConfig validation
# ---------------------------------------------------------------------------


class TestScorerConfig:
    def test_default_config_valid(self) -> None:
        config = ScorerConfig()
        assert config.initial_score == 50.0
        assert config.min_score == 0.0
        assert config.max_score == 100.0

    def test_invalid_score_range_raises(self) -> None:
        with pytest.raises(ValueError, match="min_score"):
            ScorerConfig(min_score=100.0, max_score=50.0)

    def test_invalid_violation_decay_factor_raises(self) -> None:
        with pytest.raises(ValueError, match="violation_decay_factor"):
            ScorerConfig(violation_decay_factor=1.5)

    def test_frozen(self) -> None:
        config = ScorerConfig()
        with pytest.raises((AttributeError, TypeError)):
            config.initial_score = 75.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_agent(self) -> None:
        scorer = _make_scorer()
        scorer.register_agent("agent-001")
        assert scorer.is_registered("agent-001")

    def test_register_duplicate_raises(self) -> None:
        scorer = _make_scorer()
        scorer.register_agent("agent-001")
        with pytest.raises(ValueError, match="already registered"):
            scorer.register_agent("agent-001")

    def test_initial_score_set_correctly(self) -> None:
        scorer = _make_scorer(initial_score=70.0)
        scorer.register_agent("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert abs(trust.score - 70.0) < 0.1

    def test_custom_initial_score(self) -> None:
        scorer = _make_scorer()
        scorer.register_agent("agent-001", initial_score=80.0)
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert abs(trust.score - 80.0) < 0.1

    def test_unregistered_agent_get_score_returns_none(self) -> None:
        scorer = _make_scorer()
        assert scorer.get_score("ghost") is None


# ---------------------------------------------------------------------------
# Task completion events
# ---------------------------------------------------------------------------


class TestTaskCompletion:
    def test_completion_increases_score(self) -> None:
        scorer = _make_scorer(initial_score=50.0, completion_delta=5.0)
        scorer.register_agent("agent-001")
        trust = scorer.record_completion("agent-001")
        assert trust.score > 50.0

    def test_completion_increments_counter(self) -> None:
        scorer = _make_scorer()
        trust = scorer.record_completion("agent-001")
        assert trust.total_completions == 1

    def test_multiple_completions_accumulate(self) -> None:
        scorer = _make_scorer(initial_score=50.0, completion_delta=2.0)
        for _ in range(5):
            scorer.record_completion("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.total_completions == 5
        assert trust.score > 50.0

    def test_consecutive_successes_tracked(self) -> None:
        scorer = _make_scorer()
        for _ in range(4):
            scorer.record_completion("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.consecutive_successes == 4

    def test_consecutive_success_bonus_applied(self) -> None:
        config = ScorerConfig(
            initial_score=50.0,
            completion_delta=2.0,
            consecutive_success_bonus=1.0,
            decay_per_hour=0.0,
        )
        scorer = BehavioralTrustScorer(config)
        # 4 completions: normal for first 3, bonus from the 4th
        base_5_no_bonus = 50.0 + 2.0 * 3
        for _ in range(4):
            scorer.record_completion("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.score > base_5_no_bonus


# ---------------------------------------------------------------------------
# Task failure events
# ---------------------------------------------------------------------------


class TestTaskFailure:
    def test_failure_decreases_score(self) -> None:
        scorer = _make_scorer(initial_score=50.0, failure_delta=-5.0)
        scorer.register_agent("agent-001")
        trust = scorer.record_failure("agent-001")
        assert trust.score < 50.0

    def test_failure_resets_consecutive_successes(self) -> None:
        scorer = _make_scorer()
        scorer.record_completion("agent-001")
        scorer.record_completion("agent-001")
        scorer.record_failure("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.consecutive_successes == 0

    def test_failure_counter_increments(self) -> None:
        scorer = _make_scorer()
        scorer.record_failure("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.total_failures == 1


# ---------------------------------------------------------------------------
# Policy violation events
# ---------------------------------------------------------------------------


class TestPolicyViolation:
    def test_violation_significantly_reduces_score(self) -> None:
        scorer = _make_scorer(initial_score=80.0, violation_delta=-10.0)
        trust = scorer.record_violation("agent-001")
        assert trust.score < 80.0

    def test_violation_counter_increments(self) -> None:
        scorer = _make_scorer()
        scorer.record_violation("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.total_violations == 1

    def test_violation_resets_consecutive_successes(self) -> None:
        scorer = _make_scorer()
        scorer.record_completion("agent-001")
        scorer.record_completion("agent-001")
        scorer.record_violation("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.consecutive_successes == 0

    def test_multiple_violations_drive_score_down(self) -> None:
        scorer = _make_scorer(initial_score=80.0)
        for _ in range(5):
            scorer.record_violation("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.score < 50.0


# ---------------------------------------------------------------------------
# Score bounds
# ---------------------------------------------------------------------------


class TestScoreBounds:
    def test_score_does_not_exceed_max(self) -> None:
        scorer = _make_scorer(initial_score=99.0, completion_delta=10.0)
        for _ in range(10):
            scorer.record_completion("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.score <= 100.0

    def test_score_does_not_go_below_min(self) -> None:
        scorer = _make_scorer(initial_score=5.0, violation_delta=-30.0)
        for _ in range(5):
            scorer.record_violation("agent-001")
        trust = scorer.get_score("agent-001")
        assert trust is not None
        assert trust.score >= 0.0


# ---------------------------------------------------------------------------
# BehavioralTrustScore properties
# ---------------------------------------------------------------------------


class TestBehavioralTrustScore:
    def _make_score(
        self,
        completions: int = 8,
        failures: int = 2,
        violations: int = 0,
        score: float = 75.0,
    ) -> BehavioralTrustScore:
        return BehavioralTrustScore(
            agent_id="test-agent",
            score=score,
            total_completions=completions,
            total_failures=failures,
            total_violations=violations,
            consecutive_successes=3,
            computed_at=datetime.now(timezone.utc),
        )

    def test_success_rate_calculation(self) -> None:
        trust = self._make_score(completions=8, failures=2)
        assert abs(trust.success_rate - 0.8) < 1e-9

    def test_success_rate_zero_when_no_events(self) -> None:
        trust = self._make_score(completions=0, failures=0)
        assert trust.success_rate == 0.0

    def test_trust_level_high(self) -> None:
        trust = self._make_score(score=85.0)
        assert trust.trust_level == "high"

    def test_trust_level_moderate(self) -> None:
        trust = self._make_score(score=65.0)
        assert trust.trust_level == "moderate"

    def test_trust_level_low(self) -> None:
        trust = self._make_score(score=45.0)
        assert trust.trust_level == "low"

    def test_trust_level_minimal(self) -> None:
        trust = self._make_score(score=25.0)
        assert trust.trust_level == "minimal"

    def test_trust_level_untrusted(self) -> None:
        trust = self._make_score(score=10.0)
        assert trust.trust_level == "untrusted"

    def test_to_dict_contains_all_fields(self) -> None:
        trust = self._make_score()
        data = trust.to_dict()
        required_keys = {
            "agent_id", "score", "trust_level", "total_completions",
            "total_failures", "total_violations", "consecutive_successes",
            "success_rate", "computed_at",
        }
        assert required_keys.issubset(data.keys())


# ---------------------------------------------------------------------------
# History and auto-registration
# ---------------------------------------------------------------------------


class TestHistoryAndAutoRegistration:
    def test_auto_registration_on_first_event(self) -> None:
        scorer = _make_scorer()
        scorer.record_completion("new-agent")
        assert scorer.is_registered("new-agent")

    def test_get_history_returns_events(self) -> None:
        scorer = _make_scorer()
        scorer.record_completion("agent-001", description="First task")
        scorer.record_failure("agent-001", description="Second task failed")
        history = scorer.get_history("agent-001")
        assert len(history) == 2
        assert history[0].event_type == EventType.TASK_COMPLETION
        assert history[1].event_type == EventType.TASK_FAILURE

    def test_get_history_unknown_agent_returns_empty(self) -> None:
        scorer = _make_scorer()
        assert scorer.get_history("ghost") == []

    def test_all_agents_returns_sorted_list(self) -> None:
        scorer = _make_scorer()
        scorer.register_agent("zebra")
        scorer.register_agent("alpha")
        assert scorer.all_agents() == ["alpha", "zebra"]


# ---------------------------------------------------------------------------
# Helpful action
# ---------------------------------------------------------------------------


class TestHelpfulAction:
    def test_helpful_action_increases_score(self) -> None:
        scorer = _make_scorer(initial_score=50.0)
        event = BehaviorEvent(
            event_type=EventType.HELPFUL_ACTION,
            agent_id="agent-001",
            description="Provided useful context",
        )
        trust = scorer.record_event(event)
        assert trust.score > 50.0


# ---------------------------------------------------------------------------
# Security incident
# ---------------------------------------------------------------------------


class TestSecurityIncident:
    def test_security_incident_strongly_reduces_score(self) -> None:
        scorer = _make_scorer(initial_score=70.0)
        event = BehaviorEvent(
            event_type=EventType.SECURITY_INCIDENT,
            agent_id="agent-001",
            description="Attempted unauthorized access",
        )
        trust = scorer.record_event(event)
        assert trust.score < 50.0
