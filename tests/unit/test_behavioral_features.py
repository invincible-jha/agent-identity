"""Tests for agent_identity.behavioral.features — FeatureExtractor."""
from __future__ import annotations

import math

import pytest

from agent_identity.behavioral.features import (
    ExtractedFeatures,
    FeatureExtractor,
    Observation,
    _stddev,
)


# ---------------------------------------------------------------------------
# Observation dataclass
# ---------------------------------------------------------------------------


class TestObservation:
    def test_defaults(self) -> None:
        obs = Observation(tool_name="search", latency_seconds=0.5)
        assert obs.is_error is False
        assert obs.output_tokens == 0

    def test_custom_values(self) -> None:
        obs = Observation(
            tool_name="write",
            latency_seconds=1.2,
            is_error=True,
            output_tokens=500,
        )
        assert obs.tool_name == "write"
        assert obs.is_error is True
        assert obs.output_tokens == 500


# ---------------------------------------------------------------------------
# _stddev helper
# ---------------------------------------------------------------------------


class TestStddev:
    def test_single_value_returns_zero(self) -> None:
        assert _stddev([1.0], 1.0) == 0.0

    def test_empty_list_returns_zero(self) -> None:
        assert _stddev([], 0.0) == 0.0

    def test_uniform_values_returns_zero(self) -> None:
        assert _stddev([2.0, 2.0, 2.0], 2.0) == 0.0

    def test_known_stddev(self) -> None:
        values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        mean = sum(values) / len(values)
        result = _stddev(values, mean)
        expected = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
        assert result == pytest.approx(expected)


# ---------------------------------------------------------------------------
# FeatureExtractor — ingestion
# ---------------------------------------------------------------------------


class TestFeatureExtractorIngestion:
    def test_initial_observation_count_is_zero(self) -> None:
        extractor = FeatureExtractor()
        assert extractor.observation_count == 0

    def test_add_observation_increments_count(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observation(Observation("search", 0.5))
        assert extractor.observation_count == 1

    def test_add_observations_batch(self) -> None:
        extractor = FeatureExtractor()
        observations = [
            Observation("search", 0.3),
            Observation("write", 1.1),
            Observation("read", 0.7),
        ]
        extractor.add_observations(observations)
        assert extractor.observation_count == 3

    def test_clear_resets_count_to_zero(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observation(Observation("search", 0.5))
        extractor.clear()
        assert extractor.observation_count == 0


# ---------------------------------------------------------------------------
# FeatureExtractor — extract (empty)
# ---------------------------------------------------------------------------


class TestExtractEmpty:
    def test_extract_empty_returns_defaults(self) -> None:
        extractor = FeatureExtractor()
        features = extractor.extract()
        assert features.total_calls == 0
        assert features.error_count == 0
        assert features.avg_latency == 0.0
        assert features.latency_stddev == 0.0
        assert features.error_rate == 0.0
        assert features.tool_freq == {}
        assert features.latencies == []
        assert features.response_pattern == {}


# ---------------------------------------------------------------------------
# FeatureExtractor — extract (populated)
# ---------------------------------------------------------------------------


class TestExtractPopulated:
    @pytest.fixture()
    def extractor_with_data(self) -> FeatureExtractor:
        extractor = FeatureExtractor()
        observations = [
            Observation("search", 0.5, is_error=False, output_tokens=100),
            Observation("search", 0.7, is_error=False, output_tokens=200),
            Observation("write", 1.0, is_error=True, output_tokens=50),
            Observation("read", 0.3, is_error=False, output_tokens=80),
        ]
        extractor.add_observations(observations)
        return extractor

    def test_total_calls(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        assert features.total_calls == 4

    def test_error_count(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        assert features.error_count == 1

    def test_error_rate(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        assert features.error_rate == pytest.approx(0.25)

    def test_tool_freq_counts(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        assert features.tool_freq["search"] == 2
        assert features.tool_freq["write"] == 1
        assert features.tool_freq["read"] == 1

    def test_avg_latency(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        expected = (0.5 + 0.7 + 1.0 + 0.3) / 4
        assert features.avg_latency == pytest.approx(expected)

    def test_latency_stddev_positive(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        assert features.latency_stddev > 0.0

    def test_latencies_list(self, extractor_with_data: FeatureExtractor) -> None:
        features = extractor_with_data.extract()
        assert len(features.latencies) == 4
        assert 0.5 in features.latencies

    def test_response_pattern_avg_output_tokens(
        self, extractor_with_data: FeatureExtractor
    ) -> None:
        features = extractor_with_data.extract()
        expected = (100 + 200 + 50 + 80) / 4
        assert features.response_pattern["avg_output_tokens"] == pytest.approx(expected)


# ---------------------------------------------------------------------------
# FeatureExtractor — edge cases
# ---------------------------------------------------------------------------


class TestExtractEdgeCases:
    def test_single_observation_stddev_is_zero(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observation(Observation("search", 0.5))
        features = extractor.extract()
        assert features.latency_stddev == 0.0

    def test_all_errors(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observations([
            Observation("a", 0.1, is_error=True),
            Observation("a", 0.2, is_error=True),
        ])
        features = extractor.extract()
        assert features.error_rate == pytest.approx(1.0)

    def test_no_errors(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observations([
            Observation("a", 0.1, is_error=False),
            Observation("a", 0.2, is_error=False),
        ])
        features = extractor.extract()
        assert features.error_rate == 0.0

    def test_zero_output_tokens_in_response_pattern(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observation(Observation("a", 0.5, output_tokens=0))
        features = extractor.extract()
        assert features.response_pattern["avg_output_tokens"] == 0.0

    def test_extract_after_clear_is_empty(self) -> None:
        extractor = FeatureExtractor()
        extractor.add_observation(Observation("search", 0.5))
        extractor.clear()
        features = extractor.extract()
        assert features.total_calls == 0
