"""Tests for agent_identity.behavioral.profiler — BehavioralProfiler."""
from __future__ import annotations

import pytest

from agent_identity.behavioral.features import Observation
from agent_identity.behavioral.fingerprint import BehavioralFingerprint
from agent_identity.behavioral.profiler import (
    MINIMUM_SAMPLES_FOR_BASELINE,
    BehavioralProfiler,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def profiler() -> BehavioralProfiler:
    return BehavioralProfiler(agent_id="agent-001")


def _add_observations(profiler: BehavioralProfiler, count: int) -> None:
    """Add *count* identical observations to the profiler."""
    for i in range(count):
        profiler.observe(
            tool_name="search",
            latency_seconds=0.5,
            is_error=False,
            output_tokens=100,
        )


# ---------------------------------------------------------------------------
# BehavioralProfiler — initialisation
# ---------------------------------------------------------------------------


class TestProfilerInit:
    def test_agent_id_property(self, profiler: BehavioralProfiler) -> None:
        assert profiler.agent_id == "agent-001"

    def test_initial_observation_count_is_zero(
        self, profiler: BehavioralProfiler
    ) -> None:
        assert profiler.observation_count == 0

    def test_is_not_ready_initially(self, profiler: BehavioralProfiler) -> None:
        assert profiler.is_ready() is False

    def test_custom_minimum_samples(self) -> None:
        p = BehavioralProfiler(agent_id="x", minimum_samples=5)
        _add_observations(p, 4)
        assert p.is_ready() is False
        p.observe("search", 0.5)
        assert p.is_ready() is True


# ---------------------------------------------------------------------------
# BehavioralProfiler — observe / observe_batch
# ---------------------------------------------------------------------------


class TestObserve:
    def test_observe_increments_count(self, profiler: BehavioralProfiler) -> None:
        profiler.observe("search", 0.5)
        assert profiler.observation_count == 1

    def test_observe_multiple_increments_correctly(
        self, profiler: BehavioralProfiler
    ) -> None:
        for _ in range(10):
            profiler.observe("search", 0.5)
        assert profiler.observation_count == 10

    def test_observe_batch_increments_by_batch_size(
        self, profiler: BehavioralProfiler
    ) -> None:
        batch = [
            Observation("search", 0.5),
            Observation("write", 1.0, is_error=True),
            Observation("read", 0.3, output_tokens=200),
        ]
        profiler.observe_batch(batch)
        assert profiler.observation_count == 3

    def test_observe_is_error_flag_accepted(
        self, profiler: BehavioralProfiler
    ) -> None:
        profiler.observe("write", 0.8, is_error=True)
        fp = profiler.build_fingerprint()
        assert fp.error_rate == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# BehavioralProfiler — is_ready
# ---------------------------------------------------------------------------


class TestIsReady:
    def test_not_ready_below_minimum(self, profiler: BehavioralProfiler) -> None:
        _add_observations(profiler, MINIMUM_SAMPLES_FOR_BASELINE - 1)
        assert profiler.is_ready() is False

    def test_ready_at_minimum(self, profiler: BehavioralProfiler) -> None:
        _add_observations(profiler, MINIMUM_SAMPLES_FOR_BASELINE)
        assert profiler.is_ready() is True

    def test_ready_above_minimum(self, profiler: BehavioralProfiler) -> None:
        _add_observations(profiler, MINIMUM_SAMPLES_FOR_BASELINE + 10)
        assert profiler.is_ready() is True


# ---------------------------------------------------------------------------
# BehavioralProfiler — build_fingerprint
# ---------------------------------------------------------------------------


class TestBuildFingerprint:
    def test_returns_behavioral_fingerprint(
        self, profiler: BehavioralProfiler
    ) -> None:
        profiler.observe("search", 0.5)
        fp = profiler.build_fingerprint()
        assert isinstance(fp, BehavioralFingerprint)

    def test_fingerprint_agent_id_matches(
        self, profiler: BehavioralProfiler
    ) -> None:
        profiler.observe("search", 0.5)
        fp = profiler.build_fingerprint()
        assert fp.agent_id == "agent-001"

    def test_fingerprint_tool_freq_populated(
        self, profiler: BehavioralProfiler
    ) -> None:
        profiler.observe("search", 0.5)
        profiler.observe("write", 1.0)
        profiler.observe("search", 0.4)
        fp = profiler.build_fingerprint()
        assert fp.tool_freq["search"] == 2
        assert fp.tool_freq["write"] == 1

    def test_fingerprint_avg_latency(self, profiler: BehavioralProfiler) -> None:
        profiler.observe("a", 1.0)
        profiler.observe("b", 3.0)
        fp = profiler.build_fingerprint()
        assert fp.avg_latency == pytest.approx(2.0)

    def test_fingerprint_sample_count(self, profiler: BehavioralProfiler) -> None:
        _add_observations(profiler, 10)
        fp = profiler.build_fingerprint()
        assert fp.sample_count == 10

    def test_fingerprint_error_rate(self, profiler: BehavioralProfiler) -> None:
        profiler.observe("a", 0.5, is_error=True)
        profiler.observe("b", 0.5, is_error=False)
        fp = profiler.build_fingerprint()
        assert fp.error_rate == pytest.approx(0.5)

    def test_fingerprint_from_empty_profiler(
        self, profiler: BehavioralProfiler
    ) -> None:
        fp = profiler.build_fingerprint()
        assert fp.sample_count == 0
        assert fp.avg_latency == 0.0


# ---------------------------------------------------------------------------
# BehavioralProfiler — reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_clears_observations(self, profiler: BehavioralProfiler) -> None:
        _add_observations(profiler, 5)
        profiler.reset()
        assert profiler.observation_count == 0

    def test_reset_makes_not_ready(self, profiler: BehavioralProfiler) -> None:
        _add_observations(profiler, MINIMUM_SAMPLES_FOR_BASELINE)
        assert profiler.is_ready() is True
        profiler.reset()
        assert profiler.is_ready() is False

    def test_reset_followed_by_new_observations(
        self, profiler: BehavioralProfiler
    ) -> None:
        _add_observations(profiler, 5)
        profiler.reset()
        profiler.observe("write", 2.0)
        assert profiler.observation_count == 1
