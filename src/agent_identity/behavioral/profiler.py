"""BehavioralProfiler — accumulates observations and builds behavioral profiles.

After a minimum number of samples (default 20), the profiler considers
itself ready to produce a baseline-quality BehavioralFingerprint.
"""
from __future__ import annotations

import threading

from agent_identity.behavioral.features import ExtractedFeatures, FeatureExtractor, Observation
from agent_identity.behavioral.fingerprint import BehavioralFingerprint

MINIMUM_SAMPLES_FOR_BASELINE: int = 20


class BehavioralProfiler:
    """Builds a behavioral profile for a single agent.

    Observations are accumulated in a thread-safe manner. Once the minimum
    sample threshold is reached, the profiler can generate a fingerprint
    suitable for use as a behavioral baseline.

    Parameters
    ----------
    agent_id:
        The agent this profiler is tracking.
    minimum_samples:
        Number of observations required before a reliable baseline can
        be produced.
    """

    def __init__(
        self,
        agent_id: str,
        minimum_samples: int = MINIMUM_SAMPLES_FOR_BASELINE,
    ) -> None:
        self._agent_id = agent_id
        self._minimum_samples = minimum_samples
        self._extractor = FeatureExtractor()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Observation ingestion
    # ------------------------------------------------------------------

    def observe(
        self,
        tool_name: str,
        latency_seconds: float,
        is_error: bool = False,
        output_tokens: int = 0,
    ) -> None:
        """Record a single tool invocation observation.

        Parameters
        ----------
        tool_name:
            Name of the tool or action called.
        latency_seconds:
            Duration of the call in seconds.
        is_error:
            Whether the call resulted in an error.
        output_tokens:
            Approximate number of output tokens generated.
        """
        obs = Observation(
            tool_name=tool_name,
            latency_seconds=latency_seconds,
            is_error=is_error,
            output_tokens=output_tokens,
        )
        with self._lock:
            self._extractor.add_observation(obs)

    def observe_batch(self, observations: list[Observation]) -> None:
        """Record multiple observations at once.

        Parameters
        ----------
        observations:
            List of Observation objects to record.
        """
        with self._lock:
            self._extractor.add_observations(observations)

    # ------------------------------------------------------------------
    # Profile generation
    # ------------------------------------------------------------------

    def is_ready(self) -> bool:
        """Return True if sufficient observations exist for a reliable profile."""
        with self._lock:
            return self._extractor.observation_count >= self._minimum_samples

    def build_fingerprint(self) -> BehavioralFingerprint:
        """Create a BehavioralFingerprint from accumulated observations.

        Returns
        -------
        BehavioralFingerprint
            Snapshot of current behavioral metrics.
        """
        with self._lock:
            features: ExtractedFeatures = self._extractor.extract()

        return BehavioralFingerprint(
            agent_id=self._agent_id,
            tool_freq=features.tool_freq,
            avg_latency=features.avg_latency,
            latency_stddev=features.latency_stddev,
            error_rate=features.error_rate,
            response_pattern=features.response_pattern,
            sample_count=features.total_calls,
        )

    def reset(self) -> None:
        """Clear all accumulated observations."""
        with self._lock:
            self._extractor.clear()

    @property
    def agent_id(self) -> str:
        """Return the agent ID this profiler tracks."""
        return self._agent_id

    @property
    def observation_count(self) -> int:
        """Return current number of buffered observations."""
        with self._lock:
            return self._extractor.observation_count
