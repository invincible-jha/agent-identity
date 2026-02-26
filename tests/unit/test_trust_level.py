"""Unit tests for agent_identity.trust.level — TrustLevel enum and derive_level."""
from __future__ import annotations

import pytest

from agent_identity.trust.level import LEVEL_THRESHOLDS, TrustLevel, derive_level


class TestTrustLevelEnum:
    def test_untrusted_value_is_zero(self) -> None:
        assert TrustLevel.UNTRUSTED == 0

    def test_basic_value_is_one(self) -> None:
        assert TrustLevel.BASIC == 1

    def test_standard_value_is_two(self) -> None:
        assert TrustLevel.STANDARD == 2

    def test_elevated_value_is_three(self) -> None:
        assert TrustLevel.ELEVATED == 3

    def test_full_value_is_four(self) -> None:
        assert TrustLevel.FULL == 4

    def test_ordering_untrusted_less_than_basic(self) -> None:
        assert TrustLevel.UNTRUSTED < TrustLevel.BASIC

    def test_ordering_basic_less_than_standard(self) -> None:
        assert TrustLevel.BASIC < TrustLevel.STANDARD

    def test_ordering_standard_less_than_elevated(self) -> None:
        assert TrustLevel.STANDARD < TrustLevel.ELEVATED

    def test_ordering_elevated_less_than_full(self) -> None:
        assert TrustLevel.ELEVATED < TrustLevel.FULL

    def test_full_is_maximum(self) -> None:
        all_levels = list(TrustLevel)
        assert TrustLevel.FULL == max(all_levels)

    def test_untrusted_is_minimum(self) -> None:
        all_levels = list(TrustLevel)
        assert TrustLevel.UNTRUSTED == min(all_levels)

    def test_all_five_levels_exist(self) -> None:
        assert len(TrustLevel) == 5

    def test_members_are_int_comparable(self) -> None:
        assert TrustLevel.STANDARD > 1
        assert TrustLevel.STANDARD < 3

    def test_name_strings(self) -> None:
        assert TrustLevel.UNTRUSTED.name == "UNTRUSTED"
        assert TrustLevel.BASIC.name == "BASIC"
        assert TrustLevel.STANDARD.name == "STANDARD"
        assert TrustLevel.ELEVATED.name == "ELEVATED"
        assert TrustLevel.FULL.name == "FULL"

    def test_sorted_levels_ascending(self) -> None:
        expected = [
            TrustLevel.UNTRUSTED,
            TrustLevel.BASIC,
            TrustLevel.STANDARD,
            TrustLevel.ELEVATED,
            TrustLevel.FULL,
        ]
        assert sorted(TrustLevel) == expected


class TestLevelThresholds:
    def test_untrusted_threshold_is_negative_inf(self) -> None:
        assert LEVEL_THRESHOLDS[TrustLevel.UNTRUSTED] == float("-inf")

    def test_basic_threshold_is_twenty(self) -> None:
        assert LEVEL_THRESHOLDS[TrustLevel.BASIC] == 20.0

    def test_standard_threshold_is_forty(self) -> None:
        assert LEVEL_THRESHOLDS[TrustLevel.STANDARD] == 40.0

    def test_elevated_threshold_is_sixty_five(self) -> None:
        assert LEVEL_THRESHOLDS[TrustLevel.ELEVATED] == 65.0

    def test_full_threshold_is_eighty_five(self) -> None:
        assert LEVEL_THRESHOLDS[TrustLevel.FULL] == 85.0

    def test_all_five_levels_have_thresholds(self) -> None:
        assert len(LEVEL_THRESHOLDS) == 5


class TestDeriveLevel:
    def test_negative_score_returns_untrusted(self) -> None:
        assert derive_level(-1.0) == TrustLevel.UNTRUSTED

    def test_zero_returns_untrusted(self) -> None:
        assert derive_level(0.0) == TrustLevel.UNTRUSTED

    def test_score_below_basic_threshold_returns_untrusted(self) -> None:
        assert derive_level(19.9) == TrustLevel.UNTRUSTED

    def test_score_at_basic_threshold_returns_basic(self) -> None:
        assert derive_level(20.0) == TrustLevel.BASIC

    def test_score_between_basic_and_standard_returns_basic(self) -> None:
        assert derive_level(30.0) == TrustLevel.BASIC

    def test_score_at_standard_threshold_returns_standard(self) -> None:
        assert derive_level(40.0) == TrustLevel.STANDARD

    def test_score_between_standard_and_elevated_returns_standard(self) -> None:
        assert derive_level(55.0) == TrustLevel.STANDARD

    def test_score_at_elevated_threshold_returns_elevated(self) -> None:
        assert derive_level(65.0) == TrustLevel.ELEVATED

    def test_score_between_elevated_and_full_returns_elevated(self) -> None:
        assert derive_level(75.0) == TrustLevel.ELEVATED

    def test_score_at_full_threshold_returns_full(self) -> None:
        assert derive_level(85.0) == TrustLevel.FULL

    def test_score_above_full_threshold_returns_full(self) -> None:
        assert derive_level(100.0) == TrustLevel.FULL

    def test_score_of_exactly_100_returns_full(self) -> None:
        assert derive_level(100.0) == TrustLevel.FULL

    def test_score_just_below_elevated_returns_standard(self) -> None:
        assert derive_level(64.99) == TrustLevel.STANDARD

    def test_score_just_below_full_returns_elevated(self) -> None:
        assert derive_level(84.99) == TrustLevel.ELEVATED
