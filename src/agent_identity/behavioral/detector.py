"""AnomalyDetector — z-score based behavioral anomaly detection.

Compares a current behavioral fingerprint against a stored baseline.
A z-score > threshold (default 2.0) on any metric is flagged as an anomaly.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from agent_identity.behavioral.fingerprint import BehavioralFingerprint

DEFAULT_ZSCORE_THRESHOLD: float = 2.0


@dataclass
class AnomalyResult:
    """Result of an anomaly detection check.

    Parameters
    ----------
    is_anomaly:
        True if any metric exceeded the z-score threshold.
    agent_id:
        The agent being evaluated.
    anomalous_metrics:
        Dictionary mapping metric name to its computed z-score.
    details:
        Human-readable descriptions of detected anomalies.
    """

    is_anomaly: bool
    agent_id: str
    anomalous_metrics: dict[str, float] = field(default_factory=dict)
    details: list[str] = field(default_factory=list)


class AnomalyDetector:
    """Detects behavioral anomalies using z-score comparison.

    Computes the z-score for each metric in the current fingerprint
    relative to the baseline. If any score exceeds *threshold*, the
    observation is classified as anomalous.

    Parameters
    ----------
    threshold:
        Z-score threshold above which a metric is flagged (default 2.0).
    """

    def __init__(self, threshold: float = DEFAULT_ZSCORE_THRESHOLD) -> None:
        self._threshold = threshold

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(
        self,
        current: BehavioralFingerprint,
        baseline: BehavioralFingerprint,
    ) -> AnomalyResult:
        """Compare *current* against *baseline* and flag anomalies.

        Checks latency, error_rate, and per-tool frequency. Metrics that
        have zero standard deviation in the baseline are skipped to avoid
        division-by-zero.

        Parameters
        ----------
        current:
            Most recent behavioral fingerprint.
        baseline:
            Historical baseline fingerprint to compare against.

        Returns
        -------
        AnomalyResult
            Detection outcome with per-metric z-scores and human-readable
            detail messages.
        """
        anomalous_metrics: dict[str, float] = {}
        details: list[str] = []

        self._check_scalar(
            metric_name="avg_latency",
            current_value=current.avg_latency,
            baseline_mean=baseline.avg_latency,
            baseline_stddev=baseline.latency_stddev,
            anomalous_metrics=anomalous_metrics,
            details=details,
        )

        self._check_scalar(
            metric_name="error_rate",
            current_value=current.error_rate,
            baseline_mean=baseline.error_rate,
            baseline_stddev=_error_rate_stddev(baseline.error_rate, baseline.sample_count),
            anomalous_metrics=anomalous_metrics,
            details=details,
        )

        all_tools = set(current.tool_freq.keys()) | set(baseline.tool_freq.keys())
        total_baseline = max(sum(baseline.tool_freq.values()), 1)
        total_current = max(sum(current.tool_freq.values()), 1)

        for tool in all_tools:
            baseline_rate = baseline.tool_freq.get(tool, 0) / total_baseline
            current_rate = current.tool_freq.get(tool, 0) / total_current
            stddev = _binomial_stddev(baseline_rate, total_baseline)
            self._check_scalar(
                metric_name=f"tool_freq:{tool}",
                current_value=current_rate,
                baseline_mean=baseline_rate,
                baseline_stddev=stddev,
                anomalous_metrics=anomalous_metrics,
                details=details,
            )

        return AnomalyResult(
            is_anomaly=bool(anomalous_metrics),
            agent_id=current.agent_id,
            anomalous_metrics=anomalous_metrics,
            details=details,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_scalar(
        self,
        metric_name: str,
        current_value: float,
        baseline_mean: float,
        baseline_stddev: float,
        anomalous_metrics: dict[str, float],
        details: list[str],
    ) -> None:
        """Compute z-score and record anomaly if threshold exceeded."""
        if baseline_stddev < 1e-9:
            return

        z_score = abs(current_value - baseline_mean) / baseline_stddev

        if z_score > self._threshold:
            anomalous_metrics[metric_name] = z_score
            details.append(
                f"{metric_name}: z={z_score:.2f} "
                f"(current={current_value:.4f}, "
                f"baseline_mean={baseline_mean:.4f}, "
                f"baseline_stddev={baseline_stddev:.4f})"
            )


# ------------------------------------------------------------------
# Statistical helpers
# ------------------------------------------------------------------


def _error_rate_stddev(rate: float, sample_count: int) -> float:
    """Standard deviation of a Bernoulli proportion."""
    if sample_count < 2 or rate < 1e-9 or rate > 1.0 - 1e-9:
        return 0.0
    return math.sqrt(rate * (1.0 - rate) / sample_count)


def _binomial_stddev(rate: float, sample_count: int) -> float:
    """Standard deviation for a binomial proportion estimate."""
    if sample_count < 2:
        return 0.0
    return math.sqrt(rate * (1.0 - rate) / sample_count)
