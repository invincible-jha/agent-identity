"""Unit tests for agent_identity.trust.history — TrustHistory recording and trends."""
from __future__ import annotations

import datetime

import pytest

from agent_identity.trust.history import TrustHistory


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def history() -> TrustHistory:
    return TrustHistory()


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _record_scores(
    hist: TrustHistory,
    agent_id: str,
    scores: list[float],
) -> None:
    for score in scores:
        hist.record(agent_id, composite=score, level_name="STANDARD")


# ---------------------------------------------------------------------------
# TrustHistory.record
# ---------------------------------------------------------------------------


class TestTrustHistoryRecord:
    def test_record_creates_entry_for_agent(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=50.0, level_name="STANDARD")
        entries = history.get_history("agent-001")
        assert len(entries) == 1

    def test_recorded_entry_has_correct_composite(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=75.0, level_name="ELEVATED")
        entry = history.get_history("agent-001")[0]
        assert entry["composite"] == pytest.approx(75.0)

    def test_recorded_entry_has_correct_level(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=75.0, level_name="ELEVATED")
        entry = history.get_history("agent-001")[0]
        assert entry["level"] == "ELEVATED"

    def test_recorded_entry_has_agent_id(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=50.0, level_name="STANDARD")
        entry = history.get_history("agent-001")[0]
        assert entry["agent_id"] == "agent-001"

    def test_recorded_entry_has_timestamp(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=50.0, level_name="STANDARD")
        entry = history.get_history("agent-001")[0]
        assert "timestamp" in entry

    def test_explicit_timestamp_is_stored(self, history: TrustHistory) -> None:
        ts = datetime.datetime(2025, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        history.record("agent-001", composite=50.0, level_name="STANDARD", timestamp=ts)
        entry = history.get_history("agent-001")[0]
        assert ts.isoformat() in str(entry["timestamp"])

    def test_multiple_records_appended_in_order(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [10.0, 30.0, 60.0])
        entries = history.get_history("agent-001")
        composites = [float(e["composite"]) for e in entries]  # type: ignore[arg-type]
        assert composites == [10.0, 30.0, 60.0]

    def test_records_for_different_agents_are_independent(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=50.0, level_name="STANDARD")
        history.record("agent-002", composite=80.0, level_name="FULL")
        assert len(history.get_history("agent-001")) == 1
        assert len(history.get_history("agent-002")) == 1


# ---------------------------------------------------------------------------
# TrustHistory.get_history
# ---------------------------------------------------------------------------


class TestTrustHistoryGetHistory:
    def test_get_history_empty_for_unknown_agent(self, history: TrustHistory) -> None:
        assert history.get_history("nobody") == []

    def test_since_filter_excludes_earlier_entries(self, history: TrustHistory) -> None:
        t1 = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)
        t3 = datetime.datetime(2025, 12, 1, tzinfo=datetime.timezone.utc)
        history.record("agent-001", composite=10.0, level_name="BASIC", timestamp=t1)
        history.record("agent-001", composite=50.0, level_name="STANDARD", timestamp=t2)
        history.record("agent-001", composite=90.0, level_name="FULL", timestamp=t3)
        since = datetime.datetime(2025, 5, 1, tzinfo=datetime.timezone.utc)
        entries = history.get_history("agent-001", since=since)
        assert len(entries) == 2

    def test_without_since_returns_all_entries(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [10.0, 20.0, 30.0])
        assert len(history.get_history("agent-001")) == 3


# ---------------------------------------------------------------------------
# TrustHistory.get_latest
# ---------------------------------------------------------------------------


class TestTrustHistoryGetLatest:
    def test_get_latest_returns_none_for_unknown_agent(self, history: TrustHistory) -> None:
        assert history.get_latest("nobody") is None

    def test_get_latest_returns_most_recent_entry(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [10.0, 50.0, 90.0])
        latest = history.get_latest("agent-001")
        assert latest is not None
        assert latest["composite"] == pytest.approx(90.0)

    def test_get_latest_after_single_record(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=42.0, level_name="STANDARD")
        latest = history.get_latest("agent-001")
        assert latest is not None
        assert latest["composite"] == pytest.approx(42.0)


# ---------------------------------------------------------------------------
# TrustHistory.agent_ids
# ---------------------------------------------------------------------------


class TestTrustHistoryAgentIds:
    def test_agent_ids_empty_initially(self, history: TrustHistory) -> None:
        assert history.agent_ids() == []

    def test_agent_ids_sorted(self, history: TrustHistory) -> None:
        history.record("zebra", composite=50.0, level_name="STANDARD")
        history.record("alpha", composite=50.0, level_name="STANDARD")
        history.record("mango", composite=50.0, level_name="STANDARD")
        assert history.agent_ids() == ["alpha", "mango", "zebra"]

    def test_agent_ids_no_duplicates(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [10.0, 20.0, 30.0])
        assert history.agent_ids().count("agent-001") == 1


# ---------------------------------------------------------------------------
# TrustHistory.clear_agent
# ---------------------------------------------------------------------------


class TestTrustHistoryClearAgent:
    def test_clear_removes_all_entries(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [10.0, 20.0, 30.0])
        history.clear_agent("agent-001")
        assert history.get_history("agent-001") == []

    def test_clear_unknown_agent_is_noop(self, history: TrustHistory) -> None:
        history.clear_agent("nobody")  # should not raise

    def test_clear_only_affects_target_agent(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [50.0])
        _record_scores(history, "agent-002", [60.0])
        history.clear_agent("agent-001")
        assert len(history.get_history("agent-002")) == 1


# ---------------------------------------------------------------------------
# TrustHistory.get_trend
# ---------------------------------------------------------------------------


class TestTrustHistoryGetTrend:
    def test_trend_is_stable_with_no_records(self, history: TrustHistory) -> None:
        assert history.get_trend("nobody") == "stable"

    def test_trend_is_stable_with_single_record(self, history: TrustHistory) -> None:
        history.record("agent-001", composite=50.0, level_name="STANDARD")
        assert history.get_trend("agent-001") == "stable"

    def test_improving_trend_detected(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [30.0, 40.0, 50.0, 60.0, 70.0])
        assert history.get_trend("agent-001") == "improving"

    def test_declining_trend_detected(self, history: TrustHistory) -> None:
        _record_scores(history, "agent-001", [70.0, 60.0, 50.0, 40.0, 30.0])
        assert history.get_trend("agent-001") == "declining"

    def test_stable_trend_within_threshold(self, history: TrustHistory) -> None:
        # threshold default is 3.0 — changes of < 3.0 are stable
        _record_scores(history, "agent-001", [50.0, 50.5, 51.0, 51.5, 52.0])
        assert history.get_trend("agent-001") == "stable"

    def test_custom_trend_window_respected(self) -> None:
        hist = TrustHistory(trend_window=2, trend_threshold=3.0)
        _record_scores(hist, "agent-001", [10.0, 50.0, 90.0])
        # window of 2 looks at last 2: [50.0, 90.0] → delta=40 → improving
        assert hist.get_trend("agent-001") == "improving"

    def test_custom_threshold_respected(self) -> None:
        hist = TrustHistory(trend_window=5, trend_threshold=50.0)
        _record_scores(hist, "agent-001", [30.0, 40.0, 50.0, 60.0, 70.0])
        # delta = 40.0 < 50.0 threshold → stable
        assert hist.get_trend("agent-001") == "stable"
