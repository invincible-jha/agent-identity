"""Tests for agent_identity.middleware.audit — IdentityAuditLogger."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from agent_identity.middleware.audit import AuditEvent, IdentityAuditLogger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def logger_in_memory() -> IdentityAuditLogger:
    return IdentityAuditLogger(log_path=None)


@pytest.fixture()
def log_file(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture()
def logger_on_disk(log_file: Path) -> IdentityAuditLogger:
    return IdentityAuditLogger(log_path=log_file)


# ---------------------------------------------------------------------------
# AuditEvent — dataclass and to_dict
# ---------------------------------------------------------------------------


class TestAuditEvent:
    def test_to_dict_contains_required_fields(self) -> None:
        event = AuditEvent(event_type="agent_registered", agent_id="agent-001")
        d = event.to_dict()
        assert d["event_type"] == "agent_registered"
        assert d["agent_id"] == "agent-001"
        assert d["actor_id"] == "system"
        assert "timestamp" in d
        assert "details" in d

    def test_to_dict_includes_custom_details(self) -> None:
        event = AuditEvent(
            event_type="trust_updated",
            agent_id="agent-001",
            details={"old_level": "LOW", "new_level": "HIGH"},
        )
        d = event.to_dict()
        assert d["details"]["old_level"] == "LOW"

    def test_custom_actor_id(self) -> None:
        event = AuditEvent(
            event_type="auth_success",
            agent_id="agent-002",
            actor_id="admin-user",
        )
        d = event.to_dict()
        assert d["actor_id"] == "admin-user"

    def test_timestamp_defaults_to_utc_now(self) -> None:
        before = datetime.datetime.now(datetime.timezone.utc)
        event = AuditEvent(event_type="x", agent_id="y")
        after = datetime.datetime.now(datetime.timezone.utc)
        ts = datetime.datetime.fromisoformat(event.to_dict()["timestamp"])  # type: ignore[arg-type]
        assert before <= ts <= after


# ---------------------------------------------------------------------------
# IdentityAuditLogger — in-memory mode
# ---------------------------------------------------------------------------


class TestInMemoryLogger:
    def test_log_event_buffered_in_memory(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        event = AuditEvent(event_type="test_event", agent_id="agent-001")
        logger_in_memory.log(event)
        buffer = logger_in_memory.drain_buffer()
        assert len(buffer) == 1

    def test_buffer_contains_valid_json(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        event = AuditEvent(event_type="test_event", agent_id="agent-001")
        logger_in_memory.log(event)
        buffer = logger_in_memory.drain_buffer()
        parsed = json.loads(buffer[0])
        assert parsed["event_type"] == "test_event"

    def test_drain_buffer_clears_buffer(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        logger_in_memory.log(AuditEvent(event_type="e", agent_id="a"))
        logger_in_memory.drain_buffer()
        assert logger_in_memory.drain_buffer() == []

    def test_multiple_events_buffered_in_order(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        for i in range(3):
            logger_in_memory.log(
                AuditEvent(event_type=f"event_{i}", agent_id="agent-001")
            )
        buffer = logger_in_memory.drain_buffer()
        assert len(buffer) == 3
        event_types = [json.loads(line)["event_type"] for line in buffer]
        assert event_types == ["event_0", "event_1", "event_2"]

    def test_log_event_convenience_wrapper(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        logger_in_memory.log_event(
            "custom_event", agent_id="agent-001", actor_id="sys", foo="bar"
        )
        buffer = logger_in_memory.drain_buffer()
        parsed = json.loads(buffer[0])
        assert parsed["event_type"] == "custom_event"
        assert parsed["details"]["foo"] == "bar"


# ---------------------------------------------------------------------------
# IdentityAuditLogger — disk mode
# ---------------------------------------------------------------------------


class TestDiskLogger:
    def test_log_creates_file(
        self, logger_on_disk: IdentityAuditLogger, log_file: Path
    ) -> None:
        logger_on_disk.log(AuditEvent(event_type="e", agent_id="a"))
        assert log_file.exists()

    def test_log_appends_jsonl(
        self, logger_on_disk: IdentityAuditLogger, log_file: Path
    ) -> None:
        logger_on_disk.log(AuditEvent(event_type="event_1", agent_id="a"))
        logger_on_disk.log(AuditEvent(event_type="event_2", agent_id="a"))
        lines = [l for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) == 2

    def test_read_log_returns_parsed_events(
        self, logger_on_disk: IdentityAuditLogger
    ) -> None:
        logger_on_disk.log(AuditEvent(event_type="e1", agent_id="agent-001"))
        logger_on_disk.log(AuditEvent(event_type="e2", agent_id="agent-002"))
        events = logger_on_disk.read_log()
        assert len(events) == 2
        assert events[0]["event_type"] == "e1"

    def test_read_log_with_tail(
        self, logger_on_disk: IdentityAuditLogger
    ) -> None:
        for i in range(5):
            logger_on_disk.log(AuditEvent(event_type=f"e{i}", agent_id="a"))
        events = logger_on_disk.read_log(tail=2)
        assert len(events) == 2
        assert events[-1]["event_type"] == "e4"

    def test_log_path_parent_created_if_missing(self, tmp_path: Path) -> None:
        deep = tmp_path / "nested" / "dir" / "audit.jsonl"
        logger = IdentityAuditLogger(log_path=deep)
        logger.log(AuditEvent(event_type="x", agent_id="y"))
        assert deep.exists()


# ---------------------------------------------------------------------------
# IdentityAuditLogger — read_log (memory fallback when no path)
# ---------------------------------------------------------------------------


class TestReadLogInMemory:
    def test_read_log_returns_buffer_when_no_path(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        logger_in_memory.log(AuditEvent(event_type="ev", agent_id="a"))
        events = logger_in_memory.read_log()
        assert len(events) == 1
        assert events[0]["event_type"] == "ev"

    def test_read_log_empty_when_buffer_empty(
        self, logger_in_memory: IdentityAuditLogger
    ) -> None:
        assert logger_in_memory.read_log() == []

    def test_read_log_path_not_exists_returns_buffer(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "nonexistent.jsonl"
        logger = IdentityAuditLogger(log_path=path)
        # File does not exist — read_log should return buffer (empty)
        assert logger.read_log() == []


# ---------------------------------------------------------------------------
# IdentityAuditLogger — convenience event loggers
# ---------------------------------------------------------------------------


class TestConvenienceLoggers:
    def test_log_registration(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_registration("agent-001", actor_id="admin")
        buf = logger_in_memory.drain_buffer()
        parsed = json.loads(buf[0])
        assert parsed["event_type"] == "agent_registered"
        assert parsed["agent_id"] == "agent-001"

    def test_log_deregistration(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_deregistration("agent-001")
        buf = logger_in_memory.drain_buffer()
        assert json.loads(buf[0])["event_type"] == "agent_deregistered"

    def test_log_verification_success(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_verification("agent-001", success=True)
        buf = logger_in_memory.drain_buffer()
        assert json.loads(buf[0])["event_type"] == "identity_verified"

    def test_log_verification_failure(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_verification("agent-001", success=False)
        buf = logger_in_memory.drain_buffer()
        assert json.loads(buf[0])["event_type"] == "identity_verification_failed"

    def test_log_trust_update(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_trust_update(
            agent_id="agent-001",
            old_level="LOW",
            new_level="HIGH",
            composite=0.85,
        )
        buf = logger_in_memory.drain_buffer()
        parsed = json.loads(buf[0])
        assert parsed["event_type"] == "trust_updated"
        assert parsed["details"]["old_level"] == "LOW"
        assert parsed["details"]["composite"] == pytest.approx(0.85)

    def test_log_delegation(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_delegation(
            issuer_id="agent-001",
            delegate_id="agent-002",
            token_id="tok-abc",
            scopes=["read"],
        )
        buf = logger_in_memory.drain_buffer()
        parsed = json.loads(buf[0])
        assert parsed["event_type"] == "delegation_created"
        assert parsed["details"]["token_id"] == "tok-abc"

    def test_log_revocation(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_revocation(agent_id="agent-002", token_id="tok-abc")
        buf = logger_in_memory.drain_buffer()
        parsed = json.loads(buf[0])
        assert parsed["event_type"] == "delegation_revoked"
        assert parsed["details"]["token_id"] == "tok-abc"

    def test_log_auth_attempt_success(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_auth_attempt(
            agent_id="agent-001", mechanism="bearer", success=True
        )
        buf = logger_in_memory.drain_buffer()
        parsed = json.loads(buf[0])
        assert parsed["event_type"] == "auth_success"

    def test_log_auth_attempt_failure(self, logger_in_memory: IdentityAuditLogger) -> None:
        logger_in_memory.log_auth_attempt(
            agent_id="agent-001", mechanism="certificate", success=False
        )
        buf = logger_in_memory.drain_buffer()
        parsed = json.loads(buf[0])
        assert parsed["event_type"] == "auth_failure"
        assert parsed["details"]["mechanism"] == "certificate"
