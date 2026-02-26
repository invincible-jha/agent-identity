"""Unit tests for agent_identity.trust.dimensions — TrustDimension enum and constants."""
from __future__ import annotations

import pytest

from agent_identity.trust.dimensions import (
    DEFAULT_WEIGHTS,
    OUTCOME_DELTAS,
    TrustDimension,
)


class TestTrustDimensionEnum:
    def test_competence_string_value(self) -> None:
        assert TrustDimension.COMPETENCE == "competence"

    def test_reliability_string_value(self) -> None:
        assert TrustDimension.RELIABILITY == "reliability"

    def test_integrity_string_value(self) -> None:
        assert TrustDimension.INTEGRITY == "integrity"

    def test_exactly_three_dimensions(self) -> None:
        assert len(TrustDimension) == 3

    def test_is_str_subclass(self) -> None:
        assert isinstance(TrustDimension.COMPETENCE, str)

    def test_members_are_iterable(self) -> None:
        names = {d.name for d in TrustDimension}
        assert names == {"COMPETENCE", "RELIABILITY", "INTEGRITY"}

    def test_dimension_lookup_by_value(self) -> None:
        assert TrustDimension("competence") == TrustDimension.COMPETENCE

    def test_dimension_lookup_reliability_by_value(self) -> None:
        assert TrustDimension("reliability") == TrustDimension.RELIABILITY

    def test_dimension_lookup_integrity_by_value(self) -> None:
        assert TrustDimension("integrity") == TrustDimension.INTEGRITY


class TestDefaultWeights:
    def test_all_three_dimensions_have_weights(self) -> None:
        assert set(DEFAULT_WEIGHTS.keys()) == set(TrustDimension)

    def test_competence_weight_is_forty_percent(self) -> None:
        assert DEFAULT_WEIGHTS[TrustDimension.COMPETENCE] == pytest.approx(0.40)

    def test_reliability_weight_is_thirty_five_percent(self) -> None:
        assert DEFAULT_WEIGHTS[TrustDimension.RELIABILITY] == pytest.approx(0.35)

    def test_integrity_weight_is_twenty_five_percent(self) -> None:
        assert DEFAULT_WEIGHTS[TrustDimension.INTEGRITY] == pytest.approx(0.25)

    def test_weights_sum_to_one(self) -> None:
        total = sum(DEFAULT_WEIGHTS.values())
        assert total == pytest.approx(1.0)

    def test_all_weights_are_positive(self) -> None:
        for weight in DEFAULT_WEIGHTS.values():
            assert weight > 0.0


class TestOutcomeDeltas:
    def test_success_outcome_exists(self) -> None:
        assert "success" in OUTCOME_DELTAS

    def test_failure_outcome_exists(self) -> None:
        assert "failure" in OUTCOME_DELTAS

    def test_violation_outcome_exists(self) -> None:
        assert "violation" in OUTCOME_DELTAS

    def test_success_competence_delta_is_positive(self) -> None:
        assert OUTCOME_DELTAS["success"][TrustDimension.COMPETENCE] > 0

    def test_failure_competence_delta_is_negative(self) -> None:
        assert OUTCOME_DELTAS["failure"][TrustDimension.COMPETENCE] < 0

    def test_violation_competence_delta_is_zero(self) -> None:
        assert OUTCOME_DELTAS["violation"][TrustDimension.COMPETENCE] == 0.0

    def test_violation_reliability_delta_is_negative(self) -> None:
        assert OUTCOME_DELTAS["violation"][TrustDimension.RELIABILITY] < 0

    def test_violation_integrity_delta_is_most_negative(self) -> None:
        assert (
            OUTCOME_DELTAS["violation"][TrustDimension.INTEGRITY]
            < OUTCOME_DELTAS["violation"][TrustDimension.RELIABILITY]
        )

    def test_success_deltas_are_symmetric_across_dimensions(self) -> None:
        success = OUTCOME_DELTAS["success"]
        values = list(success.values())
        assert all(v == values[0] for v in values)
