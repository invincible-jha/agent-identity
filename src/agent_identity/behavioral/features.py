"""Feature extraction from a stream of behavioral observations.

Converts raw observation records (tool name, latency, error flag) into
the numeric features required by the profiler and anomaly detector.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class Observation:
    """A single behavioral observation for one agent action.

    Parameters
    ----------
    tool_name:
        Name of the tool or action invoked.
    latency_seconds:
        Wall-clock time for the action to complete.
    is_error:
        Whether the action resulted in an error.
    output_tokens:
        Approximate number of output tokens produced (optional).
    """

    tool_name: str
    latency_seconds: float
    is_error: bool = False
    output_tokens: int = 0


@dataclass
class ExtractedFeatures:
    """Aggregated features computed from a batch of observations.

    Parameters
    ----------
    tool_freq:
        Per-tool call counts.
    total_calls:
        Total number of observations processed.
    error_count:
        Number of observations flagged as errors.
    latencies:
        Raw list of latency values (retained for stddev calculation).
    avg_latency:
        Mean latency across all observations.
    latency_stddev:
        Standard deviation of latency.
    error_rate:
        Fraction of total calls that were errors.
    response_pattern:
        Additional derived metrics (avg_output_tokens, etc.).
    """

    tool_freq: dict[str, int] = field(default_factory=dict)
    total_calls: int = 0
    error_count: int = 0
    latencies: list[float] = field(default_factory=list)
    avg_latency: float = 0.0
    latency_stddev: float = 0.0
    error_rate: float = 0.0
    response_pattern: dict[str, float] = field(default_factory=dict)


class FeatureExtractor:
    """Extracts behavioral features from a stream of Observation objects.

    The extractor maintains running totals and recalculates aggregate
    statistics on demand. It is designed to be long-lived — add
    observations incrementally, then call ``extract()`` at any point.
    """

    def __init__(self) -> None:
        self._observations: list[Observation] = []

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def add_observation(self, observation: Observation) -> None:
        """Append a single observation to the internal buffer.

        Parameters
        ----------
        observation:
            The observation to record.
        """
        self._observations.append(observation)

    def add_observations(self, observations: list[Observation]) -> None:
        """Append multiple observations to the internal buffer.

        Parameters
        ----------
        observations:
            List of observations to record.
        """
        self._observations.extend(observations)

    def clear(self) -> None:
        """Discard all buffered observations."""
        self._observations.clear()

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract(self) -> ExtractedFeatures:
        """Compute and return aggregated features from buffered observations.

        Returns
        -------
        ExtractedFeatures
            Feature snapshot at the current point in time.
        """
        features = ExtractedFeatures()

        if not self._observations:
            return features

        tool_freq: dict[str, int] = {}
        latencies: list[float] = []
        error_count = 0
        total_output_tokens = 0

        for obs in self._observations:
            tool_freq[obs.tool_name] = tool_freq.get(obs.tool_name, 0) + 1
            latencies.append(obs.latency_seconds)
            if obs.is_error:
                error_count += 1
            total_output_tokens += obs.output_tokens

        total_calls = len(self._observations)
        avg_latency = sum(latencies) / total_calls
        latency_stddev = _stddev(latencies, avg_latency)
        error_rate = error_count / total_calls

        response_pattern: dict[str, float] = {}
        if total_calls > 0:
            response_pattern["avg_output_tokens"] = total_output_tokens / total_calls

        features.tool_freq = tool_freq
        features.total_calls = total_calls
        features.error_count = error_count
        features.latencies = latencies
        features.avg_latency = avg_latency
        features.latency_stddev = latency_stddev
        features.error_rate = error_rate
        features.response_pattern = response_pattern

        return features

    @property
    def observation_count(self) -> int:
        """Return the number of buffered observations."""
        return len(self._observations)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _stddev(values: list[float], mean: float) -> float:
    """Compute population standard deviation."""
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)
