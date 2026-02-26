"""Unit tests for agent_identity.trust.policy — TrustPolicy configuration model."""
from __future__ import annotations

import pytest

from agent_identity.trust.dimensions import TrustDimension
from agent_identity.trust.policy import TrustPolicy


class TestTrustPolicyDefaults:
    def test_default_success_delta(self) -> None:
        policy = TrustPolicy()
        assert policy.success_delta == pytest.approx(2.0)

    def test_default_failure_delta(self) -> None:
        policy = TrustPolicy()
        assert policy.failure_delta == pytest.approx(-5.0)

    def test_default_decay_rate_is_one(self) -> None:
        policy = TrustPolicy()
        assert policy.decay_rate == pytest.approx(1.0)

    def test_default_min_score_is_zero(self) -> None:
        policy = TrustPolicy()
        assert policy.min_score == pytest.approx(0.0)

    def test_default_max_score_is_one_hundred(self) -> None:
        policy = TrustPolicy()
        assert policy.max_score == pytest.approx(100.0)

    def test_default_dimension_weights_sum_to_one(self) -> None:
        policy = TrustPolicy()
        total = sum(policy.dimension_weights.values())
        assert total == pytest.approx(1.0)

    def test_default_violation_deltas_has_all_dimensions(self) -> None:
        policy = TrustPolicy()
        assert set(policy.violation_deltas.keys()) == set(TrustDimension)

    def test_default_integrity_violation_delta_is_negative_fifteen(self) -> None:
        policy = TrustPolicy()
        assert policy.violation_deltas[TrustDimension.INTEGRITY] == pytest.approx(-15.0)

    def test_default_reliability_violation_delta_is_negative_ten(self) -> None:
        policy = TrustPolicy()
        assert policy.violation_deltas[TrustDimension.RELIABILITY] == pytest.approx(-10.0)


class TestTrustPolicyValidateWeights:
    def test_valid_weights_do_not_raise(self) -> None:
        policy = TrustPolicy()
        policy.validate_weights()  # should not raise

    def test_weights_summing_to_one_passes(self) -> None:
        policy = TrustPolicy(
            dimension_weights={
                TrustDimension.COMPETENCE: 0.5,
                TrustDimension.RELIABILITY: 0.3,
                TrustDimension.INTEGRITY: 0.2,
            }
        )
        policy.validate_weights()  # should not raise

    def test_weights_not_summing_to_one_raises_value_error(self) -> None:
        policy = TrustPolicy(
            dimension_weights={
                TrustDimension.COMPETENCE: 0.5,
                TrustDimension.RELIABILITY: 0.5,
                TrustDimension.INTEGRITY: 0.5,
            }
        )
        with pytest.raises(ValueError, match="sum to 1.0"):
            policy.validate_weights()

    def test_all_zero_weights_raises_value_error(self) -> None:
        policy = TrustPolicy(
            dimension_weights={
                TrustDimension.COMPETENCE: 0.0,
                TrustDimension.RELIABILITY: 0.0,
                TrustDimension.INTEGRITY: 0.0,
            }
        )
        with pytest.raises(ValueError):
            policy.validate_weights()


class TestTrustPolicyCustomization:
    def test_custom_success_delta(self) -> None:
        policy = TrustPolicy(success_delta=5.0)
        assert policy.success_delta == pytest.approx(5.0)

    def test_custom_failure_delta(self) -> None:
        policy = TrustPolicy(failure_delta=-10.0)
        assert policy.failure_delta == pytest.approx(-10.0)

    def test_custom_decay_rate(self) -> None:
        policy = TrustPolicy(decay_rate=0.98)
        assert policy.decay_rate == pytest.approx(0.98)

    def test_custom_min_score(self) -> None:
        policy = TrustPolicy(min_score=-10.0)
        assert policy.min_score == pytest.approx(-10.0)

    def test_custom_max_score(self) -> None:
        policy = TrustPolicy(max_score=200.0)
        assert policy.max_score == pytest.approx(200.0)

    def test_decay_rate_must_be_between_zero_and_one(self) -> None:
        with pytest.raises(Exception):
            TrustPolicy(decay_rate=1.5)

    def test_decay_rate_of_zero_is_valid(self) -> None:
        policy = TrustPolicy(decay_rate=0.0)
        assert policy.decay_rate == pytest.approx(0.0)

    def test_decay_rate_of_one_is_valid(self) -> None:
        policy = TrustPolicy(decay_rate=1.0)
        assert policy.decay_rate == pytest.approx(1.0)
