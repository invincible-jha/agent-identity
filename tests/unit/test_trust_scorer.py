"""Unit tests for agent_identity.trust.scorer — TrustScore dataclass and TrustScorer."""
from __future__ import annotations

import datetime

import pytest

from agent_identity.trust.dimensions import TrustDimension
from agent_identity.trust.level import TrustLevel
from agent_identity.trust.policy import TrustPolicy
from agent_identity.trust.scorer import TrustScore, TrustScorer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_scorer() -> TrustScorer:
    return TrustScorer()


@pytest.fixture()
def all_fifty_dimensions() -> dict[TrustDimension, float]:
    return {
        TrustDimension.COMPETENCE: 50.0,
        TrustDimension.RELIABILITY: 50.0,
        TrustDimension.INTEGRITY: 50.0,
    }


# ---------------------------------------------------------------------------
# TrustScore dataclass
# ---------------------------------------------------------------------------


class TestTrustScore:
    def test_to_dict_contains_agent_id(self) -> None:
        score = TrustScore(
            agent_id="agent-001",
            dimensions={
                TrustDimension.COMPETENCE: 50.0,
                TrustDimension.RELIABILITY: 50.0,
                TrustDimension.INTEGRITY: 50.0,
            },
            composite=50.0,
            level=TrustLevel.STANDARD,
        )
        assert score.to_dict()["agent_id"] == "agent-001"

    def test_to_dict_contains_composite(self) -> None:
        score = TrustScore(
            agent_id="agent-001",
            dimensions={d: 50.0 for d in TrustDimension},
            composite=50.0,
            level=TrustLevel.STANDARD,
        )
        assert score.to_dict()["composite"] == pytest.approx(50.0)

    def test_to_dict_level_is_string_name(self) -> None:
        score = TrustScore(
            agent_id="agent-001",
            dimensions={d: 50.0 for d in TrustDimension},
            composite=50.0,
            level=TrustLevel.STANDARD,
        )
        assert score.to_dict()["level"] == "STANDARD"

    def test_to_dict_dimensions_use_string_keys(self) -> None:
        score = TrustScore(
            agent_id="agent-001",
            dimensions={TrustDimension.COMPETENCE: 60.0},
            composite=60.0,
            level=TrustLevel.STANDARD,
        )
        dims = score.to_dict()["dimensions"]
        assert isinstance(dims, dict)
        assert "competence" in dims  # type: ignore[operator]

    def test_to_dict_timestamp_is_iso_string(self) -> None:
        score = TrustScore(
            agent_id="agent-001",
            dimensions={d: 50.0 for d in TrustDimension},
            composite=50.0,
            level=TrustLevel.STANDARD,
        )
        ts = score.to_dict()["timestamp"]
        assert isinstance(ts, str)
        datetime.datetime.fromisoformat(str(ts))  # should not raise

    def test_default_timestamp_is_utc_aware(self) -> None:
        score = TrustScore(
            agent_id="agent-001",
            dimensions={d: 50.0 for d in TrustDimension},
            composite=50.0,
            level=TrustLevel.STANDARD,
        )
        assert score.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# TrustScorer.score
# ---------------------------------------------------------------------------


class TestTrustScorerScore:
    def test_score_returns_trust_score_instance(
        self, default_scorer: TrustScorer, all_fifty_dimensions: dict[TrustDimension, float]
    ) -> None:
        result = default_scorer.score("agent-001", all_fifty_dimensions)
        assert isinstance(result, TrustScore)

    def test_score_sets_agent_id(
        self, default_scorer: TrustScorer, all_fifty_dimensions: dict[TrustDimension, float]
    ) -> None:
        result = default_scorer.score("agent-007", all_fifty_dimensions)
        assert result.agent_id == "agent-007"

    def test_score_at_fifty_returns_standard_level(
        self, default_scorer: TrustScorer, all_fifty_dimensions: dict[TrustDimension, float]
    ) -> None:
        result = default_scorer.score("agent-001", all_fifty_dimensions)
        assert result.level == TrustLevel.STANDARD

    def test_score_composite_is_fifty_when_all_dimensions_fifty(
        self, default_scorer: TrustScorer, all_fifty_dimensions: dict[TrustDimension, float]
    ) -> None:
        result = default_scorer.score("agent-001", all_fifty_dimensions)
        assert result.composite == pytest.approx(50.0)

    def test_score_at_ninety_returns_full_level(self, default_scorer: TrustScorer) -> None:
        dimensions = {d: 90.0 for d in TrustDimension}
        result = default_scorer.score("agent-001", dimensions)
        assert result.level == TrustLevel.FULL

    def test_score_at_ten_returns_untrusted_level(self, default_scorer: TrustScorer) -> None:
        dimensions = {d: 10.0 for d in TrustDimension}
        result = default_scorer.score("agent-001", dimensions)
        assert result.level == TrustLevel.UNTRUSTED

    def test_missing_dimension_defaults_to_zero(self, default_scorer: TrustScorer) -> None:
        result = default_scorer.score("agent-001", {})
        assert result.composite == pytest.approx(0.0)

    def test_clamping_above_max_score(self, default_scorer: TrustScorer) -> None:
        dimensions = {d: 200.0 for d in TrustDimension}
        result = default_scorer.score("agent-001", dimensions)
        assert result.composite <= 100.0

    def test_clamping_below_min_score(self, default_scorer: TrustScorer) -> None:
        dimensions = {d: -50.0 for d in TrustDimension}
        result = default_scorer.score("agent-001", dimensions)
        assert result.composite >= 0.0

    def test_weighted_composite_calculation(self, default_scorer: TrustScorer) -> None:
        # competence=100, reliability=0, integrity=0
        # composite = 100*0.40 + 0*0.35 + 0*0.25 = 40.0
        dimensions = {
            TrustDimension.COMPETENCE: 100.0,
            TrustDimension.RELIABILITY: 0.0,
            TrustDimension.INTEGRITY: 0.0,
        }
        result = default_scorer.score("agent-001", dimensions)
        assert result.composite == pytest.approx(40.0)

    def test_all_dimensions_present_in_result(
        self, default_scorer: TrustScorer, all_fifty_dimensions: dict[TrustDimension, float]
    ) -> None:
        result = default_scorer.score("agent-001", all_fifty_dimensions)
        assert set(result.dimensions.keys()) == set(TrustDimension)


# ---------------------------------------------------------------------------
# TrustScorer.apply_outcome
# ---------------------------------------------------------------------------


class TestTrustScorerApplyOutcome:
    def test_success_increases_all_dimensions(self, default_scorer: TrustScorer) -> None:
        current = {d: 50.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "success")
        for dim in TrustDimension:
            assert updated[dim] > current[dim]

    def test_failure_decreases_all_dimensions(self, default_scorer: TrustScorer) -> None:
        current = {d: 50.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "failure")
        for dim in TrustDimension:
            assert updated[dim] < current[dim]

    def test_violation_decreases_reliability_and_integrity(
        self, default_scorer: TrustScorer
    ) -> None:
        current = {d: 50.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "violation")
        assert updated[TrustDimension.RELIABILITY] < current[TrustDimension.RELIABILITY]
        assert updated[TrustDimension.INTEGRITY] < current[TrustDimension.INTEGRITY]

    def test_violation_does_not_change_competence(self, default_scorer: TrustScorer) -> None:
        current = {d: 50.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "violation")
        assert updated[TrustDimension.COMPETENCE] == pytest.approx(50.0)

    def test_unknown_outcome_raises_value_error(self, default_scorer: TrustScorer) -> None:
        current = {d: 50.0 for d in TrustDimension}
        with pytest.raises(ValueError, match="Unrecognised outcome"):
            default_scorer.apply_outcome(current, "unknown")

    def test_score_does_not_drop_below_min(self, default_scorer: TrustScorer) -> None:
        current = {d: 0.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "failure")
        for val in updated.values():
            assert val >= 0.0

    def test_score_does_not_exceed_max(self, default_scorer: TrustScorer) -> None:
        current = {d: 100.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "success")
        for val in updated.values():
            assert val <= 100.0

    def test_decay_rate_applied_before_delta(self) -> None:
        policy = TrustPolicy(decay_rate=0.9, success_delta=0.0)
        scorer = TrustScorer(policy=policy)
        current = {d: 100.0 for d in TrustDimension}
        updated = scorer.apply_outcome(current, "success")
        for val in updated.values():
            assert val == pytest.approx(90.0)

    def test_all_updated_dimensions_returned(self, default_scorer: TrustScorer) -> None:
        current = {d: 50.0 for d in TrustDimension}
        updated = default_scorer.apply_outcome(current, "success")
        assert set(updated.keys()) == set(TrustDimension)


# ---------------------------------------------------------------------------
# TrustScorer constructor
# ---------------------------------------------------------------------------


class TestTrustScorerConstructor:
    def test_invalid_weights_raise_on_construction(self) -> None:
        bad_policy = TrustPolicy(
            dimension_weights={
                TrustDimension.COMPETENCE: 0.6,
                TrustDimension.RELIABILITY: 0.6,
                TrustDimension.INTEGRITY: 0.6,
            }
        )
        with pytest.raises(ValueError):
            TrustScorer(policy=bad_policy)

    def test_default_constructor_uses_standard_policy(self) -> None:
        scorer = TrustScorer()
        assert scorer is not None

    def test_custom_policy_accepted(self) -> None:
        policy = TrustPolicy(success_delta=10.0)
        scorer = TrustScorer(policy=policy)
        assert scorer is not None
