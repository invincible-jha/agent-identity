"""TrustHistory — tracks trust score changes over time per agent.

Maintains an ordered log of TrustScore snapshots. Provides trend analysis
(improving / declining / stable) based on composite score movement.
"""
from __future__ import annotations

import datetime
import threading
from collections import defaultdict


class TrustHistory:
    """In-memory time-series store for trust score snapshots.

    Each recorded snapshot is a lightweight dict containing only the fields
    needed for history analysis: composite score, level name, and timestamp.
    This avoids importing TrustScore at runtime to keep the class lightweight
    and importable without circular dependency concerns.

    Parameters
    ----------
    trend_window:
        Number of most-recent records to use when computing the trend.
        Defaults to 5.
    trend_threshold:
        Minimum absolute change in composite score (across the trend window)
        required to call a trend "improving" or "declining". Changes smaller
        than this are considered "stable". Defaults to 3.0.
    """

    _HistoryEntry = dict[str, object]

    def __init__(
        self,
        trend_window: int = 5,
        trend_threshold: float = 3.0,
    ) -> None:
        self._records: dict[str, list[TrustHistory._HistoryEntry]] = defaultdict(list)
        self._lock = threading.Lock()
        self._trend_window = trend_window
        self._trend_threshold = trend_threshold

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(
        self,
        agent_id: str,
        composite: float,
        level_name: str,
        timestamp: datetime.datetime | None = None,
    ) -> None:
        """Append a trust snapshot for an agent.

        Parameters
        ----------
        agent_id:
            The agent whose trust score is being recorded.
        composite:
            The composite trust score at this point in time.
        level_name:
            The string name of the TrustLevel (e.g. "STANDARD").
        timestamp:
            UTC datetime of the observation. Defaults to now.
        """
        ts = timestamp if timestamp is not None else datetime.datetime.now(
            datetime.timezone.utc
        )
        entry: TrustHistory._HistoryEntry = {
            "agent_id": agent_id,
            "composite": composite,
            "level": level_name,
            "timestamp": ts.isoformat(),
        }
        with self._lock:
            self._records[agent_id].append(entry)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_history(
        self,
        agent_id: str,
        since: datetime.datetime | None = None,
    ) -> list[dict[str, object]]:
        """Return recorded snapshots for an agent, optionally filtered by time.

        Parameters
        ----------
        agent_id:
            The agent whose history to retrieve.
        since:
            If provided, only entries at or after this UTC datetime are
            returned. If None, all entries are returned.

        Returns
        -------
        list[dict[str, object]]
            Chronologically ordered list of history entry dicts.
        """
        with self._lock:
            entries = list(self._records.get(agent_id, []))

        if since is None:
            return entries

        since_iso = since.isoformat()
        return [e for e in entries if str(e["timestamp"]) >= since_iso]

    def get_latest(self, agent_id: str) -> dict[str, object] | None:
        """Return the most recent snapshot for an agent, or None.

        Parameters
        ----------
        agent_id:
            The agent to query.

        Returns
        -------
        dict[str, object] or None
        """
        with self._lock:
            records = self._records.get(agent_id, [])
            return records[-1] if records else None

    def agent_ids(self) -> list[str]:
        """Return sorted list of agent IDs with recorded history."""
        with self._lock:
            return sorted(self._records.keys())

    def clear_agent(self, agent_id: str) -> None:
        """Remove all history for an agent.

        Parameters
        ----------
        agent_id:
            The agent whose history to purge.
        """
        with self._lock:
            self._records.pop(agent_id, None)

    # ------------------------------------------------------------------
    # Trend analysis
    # ------------------------------------------------------------------

    def get_trend(self, agent_id: str) -> str:
        """Compute the trust trend for an agent over the recent window.

        Compares the composite score of the oldest record in the trend window
        with the most recent record. If fewer than 2 records exist the trend
        is always "stable".

        Parameters
        ----------
        agent_id:
            The agent to analyse.

        Returns
        -------
        str
            One of "improving", "declining", or "stable".
        """
        with self._lock:
            records = list(self._records.get(agent_id, []))

        if len(records) < 2:
            return "stable"

        window = records[-self._trend_window :]
        oldest_composite = float(window[0]["composite"])  # type: ignore[arg-type]
        newest_composite = float(window[-1]["composite"])  # type: ignore[arg-type]
        delta = newest_composite - oldest_composite

        if delta >= self._trend_threshold:
            return "improving"
        if delta <= -self._trend_threshold:
            return "declining"
        return "stable"
