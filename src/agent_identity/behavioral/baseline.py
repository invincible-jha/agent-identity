"""BaselineManager — store and load behavioral baselines per agent.

Baselines are persisted as JSON files under a configurable directory.
In-memory caching avoids repeated disk reads during high-frequency checks.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from agent_identity.behavioral.fingerprint import BehavioralFingerprint


class BaselineManager:
    """Manages behavioral baselines for a fleet of agents.

    Baselines are stored as per-agent JSON files. An in-memory cache
    prevents repeated disk I/O during anomaly detection loops.

    Parameters
    ----------
    storage_dir:
        Directory where baseline JSON files are persisted.
    """

    def __init__(self, storage_dir: Path) -> None:
        self._storage_dir = storage_dir
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, BehavioralFingerprint] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_baseline(self, fingerprint: BehavioralFingerprint) -> None:
        """Persist a fingerprint as the baseline for an agent.

        Parameters
        ----------
        fingerprint:
            The fingerprint to use as the new baseline.
        """
        with self._lock:
            self._cache[fingerprint.agent_id] = fingerprint
            path = self._baseline_path(fingerprint.agent_id)
            path.write_text(
                json.dumps(fingerprint.to_dict(), indent=2), encoding="utf-8"
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def load_baseline(self, agent_id: str) -> BehavioralFingerprint | None:
        """Retrieve the stored baseline for an agent.

        Parameters
        ----------
        agent_id:
            The agent whose baseline to retrieve.

        Returns
        -------
        BehavioralFingerprint or None
            The stored baseline, or None if no baseline exists.
        """
        with self._lock:
            if agent_id in self._cache:
                return self._cache[agent_id]

            path = self._baseline_path(agent_id)
            if not path.exists():
                return None

            try:
                data: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
                fingerprint = BehavioralFingerprint.from_dict(data)
                self._cache[agent_id] = fingerprint
                return fingerprint
            except (json.JSONDecodeError, KeyError):
                return None

    def has_baseline(self, agent_id: str) -> bool:
        """Return True if a baseline exists for the given agent."""
        with self._lock:
            if agent_id in self._cache:
                return True
            return self._baseline_path(agent_id).exists()

    def delete_baseline(self, agent_id: str) -> None:
        """Remove the stored baseline for an agent.

        Parameters
        ----------
        agent_id:
            The agent whose baseline to delete.
        """
        with self._lock:
            self._cache.pop(agent_id, None)
            path = self._baseline_path(agent_id)
            if path.exists():
                path.unlink()

    def list_agents(self) -> list[str]:
        """Return sorted list of agent IDs with stored baselines."""
        return sorted(
            p.stem for p in self._storage_dir.glob("*.json")
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _baseline_path(self, agent_id: str) -> Path:
        safe_name = agent_id.replace("/", "_").replace("\\", "_")
        return self._storage_dir / f"{safe_name}.json"
