"""Tests for agent_identity.behavioral.detector — AnomalyDetector."""
from __future__ import annotations

import math

import pytest

from agent_identity.behavioral.detector import (
    DEFAULT_ZSCORE_THRESHOLD,
    AnomalyDetector,
    AnomalyResult,
    _binomial_stddev,
    _error_rate_stddev,
)
from agent_identity.behavioral.fingerprint import BehavioralFingerprint


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def make_fingerprint(
    agent_id: str = "agent-001",
    tool_freq: dict[str, int] | None = None,
    avg_latency: float = 0.5,
    latency_stddev: float = 0.1,
    error_rate: float = 0.0,
    sample_count: int = 50,
) -> BehavioralFingerprint:
    return BehavioralFingerprint(
        agent_id=agent_id,
        tool_freq=tool_freq or {"search": 40, "write": 10},
        avg_latency=avg_latency,
        latency_stddev=latency_stddev,
        error_rate=error_rate,
        sample_count=sample_count,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def detector() -> AnomalyDetector:
    return AnomalyDetector(threshold=DEFAULT_ZSCORE_THRESHOLD)


@pytest.fixture()
def baseline() -> BehavioralFingerprint:
    return make_fingerprint()


# ---------------------------------------------------------------------------
# AnomalyResult dataclass
# ---------------------------------------------------------------------------


class TestAnomalyResult:
    def test_no_anomaly_by_default(self) -> None:
        result = AnomalyResult(is_anomaly=False, agent_id="agent-001")
        assert result.is_anomaly is False
        assert result.anomalous_metrics == {}
        assert result.details == []

    def test_anomaly_with_metrics(self) -> None:
        result = AnomalyResult(
            is_anomaly=True,
            agent_id="agent-001",
            anomalous_metrics={"avg_latency": 3.5},
            details=["avg_latency: z=3.50"],
        )
        assert result.is_anomaly is True
        assert "avg_latency" in result.anomalous_metrics


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------


class TestErrorRateStddev:
    def test_zero_sample_count_returns_zero(self) -> None:
        assert _error_rate_stddev(0.05, 0) == 0.0

    def test_single_sample_returns_zero(self) -> None:
        assert _error_rate_stddev(0.05, 1) == 0.0

    def test_zero_rate_returns_zero(self) -> None:
        assert _error_rate_stddev(0.0, 100) == 0.0

    def test_rate_of_one_returns_zero(self) -> None:
        assert _error_rate_stddev(1.0, 100) == 0.0

    def test_valid_rate_returns_positive(self) -> None:
        result = _error_rate_stddev(0.1, 100)
        assert result > 0.0
        expected = math.sqrt(0.1 * 0.9 / 100)
        assert result == pytest.approx(expected)


class TestBinomialStddev:
    def test_zero_sample_count_returns_zero(self) -> None:
        assert _binomial_stddev(0.5, 0) == 0.0

    def test_single_sample_returns_zero(self) -> None:
        assert _binomial_stddev(0.5, 1) == 0.0

    def test_valid_inputs_return_positive(self) -> None:
        result = _binomial_stddev(0.4, 100)
        expected = math.sqrt(0.4 * 0.6 / 100)
        assert result == pytest.approx(expected)

    def test_zero_rate_returns_zero(self) -> None:
        # 0 * (1-0) / n = 0
        assert _binomial_stddev(0.0, 100) == 0.0


# ---------------------------------------------------------------------------
# AnomalyDetector — detect (no anomaly)
# ---------------------------------------------------------------------------


class TestDetectNoAnomaly:
    def test_identical_fingerprints_no_anomaly(
        self, detector: AnomalyDetector, baseline: BehavioralFingerprint
    ) -> None:
        # current == baseline: z-score = 0 everywhere
        result = detector.detect(current=baseline, baseline=baseline)
        assert result.is_anomaly is False
        assert result.anomalous_metrics == {}

    def test_within_threshold_no_anomaly(
        self, detector: AnomalyDetector, baseline: BehavioralFingerprint
    ) -> None:
        current = make_fingerprint(
            avg_latency=0.51,  # barely different
            latency_stddev=0.1,
            error_rate=0.0,
        )
        result = detector.detect(current=current, baseline=baseline)
        assert result.is_anomaly is False

    def test_zero_stddev_skips_metric(
        self, detector: AnomalyDetector
    ) -> None:
        """A metric with zero baseline stddev is skipped (division by zero guard)."""
        baseline = make_fingerprint(latency_stddev=0.0)
        current = make_fingerprint(avg_latency=100.0, latency_stddev=0.0)
        result = detector.detect(current=current, baseline=baseline)
        # avg_latency is skipped due to zero stddev — only error_rate matters
        assert "avg_latency" not in result.anomalous_metrics


# ---------------------------------------------------------------------------
# AnomalyDetector — detect (anomaly detected)
# ---------------------------------------------------------------------------


class TestDetectAnomaly:
    def test_high_latency_triggers_anomaly(
        self, detector: AnomalyDetector, baseline: BehavioralFingerprint
    ) -> None:
        # baseline latency=0.5, stddev=0.1, threshold=2.0
        # z-score = |5.0 - 0.5| / 0.1 = 45 >> 2.0
        current = make_fingerprint(avg_latency=5.0, latency_stddev=0.1)
        result = detector.detect(current=current, baseline=baseline)
        assert result.is_anomaly is True
        assert "avg_latency" in result.anomalous_metrics
        assert result.anomalous_metrics["avg_latency"] > 2.0

    def test_anomaly_details_not_empty(
        self, detector: AnomalyDetector, baseline: BehavioralFingerprint
    ) -> None:
        current = make_fingerprint(avg_latency=5.0)
        result = detector.detect(current=current, baseline=baseline)
        assert len(result.details) > 0

    def test_error_rate_spike_triggers_anomaly(
        self, detector: AnomalyDetector
    ) -> None:
        baseline = make_fingerprint(error_rate=0.05, sample_count=200)
        # z-score on error rate: stddev = sqrt(0.05*0.95/200) ≈ 0.0154
        # |0.30 - 0.05| / 0.0154 ≈ 16.2 >> 2.0
        current = make_fingerprint(error_rate=0.30, sample_count=200)
        result = detector.detect(current=current, baseline=baseline)
        assert result.is_anomaly is True
        assert "error_rate" in result.anomalous_metrics

    def test_tool_freq_shift_triggers_anomaly(
        self, detector: AnomalyDetector
    ) -> None:
        """Shift in tool usage rates triggers an anomaly when baseline has non-zero stddev.

        With 100 samples and a baseline search rate of 0.7, binomial stddev ~= 0.0458.
        A current rate of 0.1 yields z = |0.1 - 0.7| / 0.0458 ~= 13.1 >> 2.0.
        """
        baseline = make_fingerprint(
            tool_freq={"search": 70, "write": 30},
            sample_count=100,
            avg_latency=0.5,
            latency_stddev=0.0,  # keep latency out of the mix
        )
        current = make_fingerprint(
            tool_freq={"search": 10, "write": 90},
            sample_count=100,
            avg_latency=0.5,
            latency_stddev=0.0,
        )
        result = detector.detect(current=current, baseline=baseline)
        assert result.is_anomaly is True

    def test_agent_id_propagated_to_result(
        self, detector: AnomalyDetector, baseline: BehavioralFingerprint
    ) -> None:
        current = make_fingerprint(agent_id="my-agent")
        result = detector.detect(current=current, baseline=baseline)
        assert result.agent_id == "my-agent"

    def test_custom_threshold_less_sensitive(self) -> None:
        relaxed_detector = AnomalyDetector(threshold=10.0)
        baseline = make_fingerprint(avg_latency=0.5, latency_stddev=0.1)
        # z=5.0 would trigger default threshold=2.0 but not threshold=10.0
        current = make_fingerprint(avg_latency=1.0, latency_stddev=0.1)
        result = relaxed_detector.detect(current=current, baseline=baseline)
        assert result.is_anomaly is False

    def test_custom_threshold_more_sensitive(self) -> None:
        strict_detector = AnomalyDetector(threshold=0.5)
        baseline = make_fingerprint(avg_latency=0.5, latency_stddev=0.1)
        # z = |0.6 - 0.5| / 0.1 = 1.0 > 0.5
        current = make_fingerprint(avg_latency=0.6, latency_stddev=0.1)
        result = strict_detector.detect(current=current, baseline=baseline)
        assert result.is_anomaly is True
