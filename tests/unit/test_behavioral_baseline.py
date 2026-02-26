"""Tests for agent_identity.behavioral.baseline — BaselineManager."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_identity.behavioral.baseline import BaselineManager
from agent_identity.behavioral.fingerprint import BehavioralFingerprint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def storage_dir(tmp_path: Path) -> Path:
    return tmp_path / "baselines"


@pytest.fixture()
def manager(storage_dir: Path) -> BaselineManager:
    return BaselineManager(storage_dir=storage_dir)


@pytest.fixture()
def fingerprint_a() -> BehavioralFingerprint:
    return BehavioralFingerprint(
        agent_id="agent-001",
        tool_freq={"search": 10, "write": 5},
        avg_latency=0.5,
        latency_stddev=0.1,
        error_rate=0.02,
        response_pattern={"avg_output_tokens": 120.0},
        sample_count=15,
    )


@pytest.fixture()
def fingerprint_b() -> BehavioralFingerprint:
    return BehavioralFingerprint(
        agent_id="agent-002",
        tool_freq={"read": 20},
        avg_latency=1.2,
        latency_stddev=0.3,
        error_rate=0.0,
        sample_count=20,
    )


# ---------------------------------------------------------------------------
# BaselineManager — initialisation
# ---------------------------------------------------------------------------


class TestBaselineManagerInit:
    def test_creates_storage_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "baselines"
        assert not target.exists()
        BaselineManager(storage_dir=target)
        assert target.is_dir()

    def test_accepts_existing_directory(self, tmp_path: Path) -> None:
        BaselineManager(storage_dir=tmp_path)  # should not raise


# ---------------------------------------------------------------------------
# BaselineManager — save_baseline / load_baseline
# ---------------------------------------------------------------------------


class TestSaveAndLoad:
    def test_save_persists_json_file(
        self, manager: BaselineManager, storage_dir: Path, fingerprint_a: BehavioralFingerprint
    ) -> None:
        manager.save_baseline(fingerprint_a)
        expected_path = storage_dir / "agent-001.json"
        assert expected_path.exists()

    def test_load_returns_correct_fingerprint(
        self, manager: BaselineManager, fingerprint_a: BehavioralFingerprint
    ) -> None:
        manager.save_baseline(fingerprint_a)
        loaded = manager.load_baseline("agent-001")
        assert loaded is not None
        assert loaded.agent_id == "agent-001"
        assert loaded.avg_latency == pytest.approx(0.5)
        assert loaded.tool_freq == {"search": 10, "write": 5}

    def test_load_missing_agent_returns_none(self, manager: BaselineManager) -> None:
        result = manager.load_baseline("nonexistent-agent")
        assert result is None

    def test_load_from_cache_avoids_disk_read(
        self,
        manager: BaselineManager,
        fingerprint_a: BehavioralFingerprint,
        storage_dir: Path,
    ) -> None:
        manager.save_baseline(fingerprint_a)
        # Delete disk file; cache should still serve it
        (storage_dir / "agent-001.json").unlink()
        loaded = manager.load_baseline("agent-001")
        assert loaded is not None
        assert loaded.agent_id == "agent-001"

    def test_save_updates_cache_immediately(
        self, manager: BaselineManager, fingerprint_a: BehavioralFingerprint
    ) -> None:
        manager.save_baseline(fingerprint_a)
        # A second load should hit cache (no disk I/O required)
        loaded = manager.load_baseline("agent-001")
        assert loaded is fingerprint_a

    def test_load_corrupted_json_returns_none(
        self, manager: BaselineManager, storage_dir: Path
    ) -> None:
        storage_dir.mkdir(parents=True, exist_ok=True)
        (storage_dir / "corrupt-agent.json").write_text("{ invalid json", encoding="utf-8")
        result = manager.load_baseline("corrupt-agent")
        assert result is None

    def test_multiple_agents_stored_independently(
        self,
        manager: BaselineManager,
        fingerprint_a: BehavioralFingerprint,
        fingerprint_b: BehavioralFingerprint,
    ) -> None:
        manager.save_baseline(fingerprint_a)
        manager.save_baseline(fingerprint_b)
        a = manager.load_baseline("agent-001")
        b = manager.load_baseline("agent-002")
        assert a is not None
        assert b is not None
        assert a.agent_id == "agent-001"
        assert b.agent_id == "agent-002"


# ---------------------------------------------------------------------------
# BaselineManager — has_baseline
# ---------------------------------------------------------------------------


class TestHasBaseline:
    def test_false_when_no_baseline_exists(self, manager: BaselineManager) -> None:
        assert manager.has_baseline("nobody") is False

    def test_true_after_save(
        self, manager: BaselineManager, fingerprint_a: BehavioralFingerprint
    ) -> None:
        manager.save_baseline(fingerprint_a)
        assert manager.has_baseline("agent-001") is True

    def test_true_via_disk_without_cache(
        self,
        storage_dir: Path,
        fingerprint_a: BehavioralFingerprint,
    ) -> None:
        """A fresh manager (no in-memory cache) should detect the file on disk."""
        first_manager = BaselineManager(storage_dir=storage_dir)
        first_manager.save_baseline(fingerprint_a)
        second_manager = BaselineManager(storage_dir=storage_dir)
        assert second_manager.has_baseline("agent-001") is True


# ---------------------------------------------------------------------------
# BaselineManager — delete_baseline
# ---------------------------------------------------------------------------


class TestDeleteBaseline:
    def test_delete_removes_file_and_cache(
        self, manager: BaselineManager, fingerprint_a: BehavioralFingerprint, storage_dir: Path
    ) -> None:
        manager.save_baseline(fingerprint_a)
        manager.delete_baseline("agent-001")
        assert not (storage_dir / "agent-001.json").exists()
        assert manager.load_baseline("agent-001") is None

    def test_delete_nonexistent_is_noop(self, manager: BaselineManager) -> None:
        manager.delete_baseline("ghost-agent")  # must not raise

    def test_has_baseline_false_after_delete(
        self, manager: BaselineManager, fingerprint_a: BehavioralFingerprint
    ) -> None:
        manager.save_baseline(fingerprint_a)
        manager.delete_baseline("agent-001")
        assert manager.has_baseline("agent-001") is False


# ---------------------------------------------------------------------------
# BaselineManager — list_agents
# ---------------------------------------------------------------------------


class TestListAgents:
    def test_empty_when_no_baselines(self, manager: BaselineManager) -> None:
        assert manager.list_agents() == []

    def test_returns_sorted_agent_ids(
        self,
        manager: BaselineManager,
        fingerprint_a: BehavioralFingerprint,
        fingerprint_b: BehavioralFingerprint,
    ) -> None:
        manager.save_baseline(fingerprint_b)
        manager.save_baseline(fingerprint_a)
        agents = manager.list_agents()
        assert agents == sorted(agents)
        assert "agent-001" in agents
        assert "agent-002" in agents

    def test_deleted_agent_not_in_list(
        self, manager: BaselineManager, fingerprint_a: BehavioralFingerprint
    ) -> None:
        manager.save_baseline(fingerprint_a)
        manager.delete_baseline("agent-001")
        assert manager.list_agents() == []


# ---------------------------------------------------------------------------
# BaselineManager — path sanitisation
# ---------------------------------------------------------------------------


class TestPathSanitisation:
    def test_forward_slash_in_agent_id_is_replaced(
        self, manager: BaselineManager, storage_dir: Path
    ) -> None:
        fp = BehavioralFingerprint(agent_id="org/agent-003", sample_count=5)
        manager.save_baseline(fp)
        # The file should be stored with _ instead of /
        assert (storage_dir / "org_agent-003.json").exists()

    def test_backslash_in_agent_id_is_replaced(
        self, manager: BaselineManager, storage_dir: Path
    ) -> None:
        fp = BehavioralFingerprint(agent_id="org\\agent-004", sample_count=5)
        manager.save_baseline(fp)
        assert (storage_dir / "org_agent-004.json").exists()
