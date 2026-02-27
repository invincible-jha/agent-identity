"""Tests for Capability-Based Access Control — E15.2."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_identity.capabilities.capability import (
    Capability,
    CapabilityChecker,
    CapabilityGrant,
    CheckResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc(offset_hours: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=offset_hours)


def _read_cap(resource: str = "database:users", expiry: datetime | None = None) -> Capability:
    return Capability(resource=resource, actions=["read"], expiry=expiry)


def _write_cap(resource: str = "database:users", expiry: datetime | None = None) -> Capability:
    return Capability(resource=resource, actions=["read", "write"], expiry=expiry)


# ---------------------------------------------------------------------------
# Capability dataclass tests
# ---------------------------------------------------------------------------


class TestCapabilityInit:
    def test_valid_capability_created(self) -> None:
        cap = Capability(resource="api:payment", actions=["read", "write"])
        assert cap.resource == "api:payment"
        assert "read" in cap.actions
        assert "write" in cap.actions

    def test_empty_resource_raises(self) -> None:
        with pytest.raises(ValueError, match="resource"):
            Capability(resource="", actions=["read"])

    def test_empty_actions_list_raises(self) -> None:
        with pytest.raises(ValueError, match="actions"):
            Capability(resource="api:data", actions=[])

    def test_empty_action_string_raises(self) -> None:
        with pytest.raises(ValueError, match="actions"):
            Capability(resource="api:data", actions=["read", ""])

    def test_no_expiry_by_default(self) -> None:
        cap = Capability(resource="tool:search", actions=["execute"])
        assert cap.expiry is None
        assert not cap.is_expired()

    def test_frozen_dataclass(self) -> None:
        cap = Capability(resource="api:data", actions=["read"])
        with pytest.raises((AttributeError, TypeError)):
            cap.resource = "other"  # type: ignore[misc]


class TestCapabilityExpiry:
    def test_not_expired_when_expiry_in_future(self) -> None:
        cap = Capability(resource="api:data", actions=["read"], expiry=_utc(+24))
        assert not cap.is_expired()

    def test_expired_when_past_expiry(self) -> None:
        cap = Capability(resource="api:data", actions=["read"], expiry=_utc(-1))
        assert cap.is_expired()

    def test_expired_exactly_at_boundary(self) -> None:
        boundary = _utc()
        cap = Capability(resource="api:data", actions=["read"], expiry=boundary)
        assert cap.is_expired(now=boundary)

    def test_custom_now_for_expiry_check(self) -> None:
        future = _utc(+24)
        cap = Capability(resource="api:data", actions=["read"], expiry=_utc(+12))
        # Checking with "future" time that is past the expiry
        assert cap.is_expired(now=future)


class TestCapabilityAllows:
    def test_allows_listed_action(self) -> None:
        cap = Capability(resource="api:data", actions=["read", "write"])
        assert cap.allows("read")
        assert cap.allows("write")

    def test_denies_unlisted_action(self) -> None:
        cap = Capability(resource="api:data", actions=["read"])
        assert not cap.allows("delete")

    def test_to_dict_structure(self) -> None:
        cap = Capability(
            resource="api:data",
            actions=["read"],
            expiry=_utc(+24),
            conditions={"env": "prod"},
            capability_id="cap-001",
        )
        data = cap.to_dict()
        assert data["resource"] == "api:data"
        assert data["actions"] == ["read"]
        assert data["expiry"] is not None
        assert data["conditions"] == {"env": "prod"}
        assert data["capability_id"] == "cap-001"


# ---------------------------------------------------------------------------
# CapabilityGrant tests
# ---------------------------------------------------------------------------


class TestCapabilityGrant:
    def test_grant_adds_capability(self) -> None:
        grant = CapabilityGrant(agent_id="agent-001")
        grant.grant(_read_cap())
        assert len(grant.all_capabilities()) == 1

    def test_active_capabilities_excludes_expired(self) -> None:
        grant = CapabilityGrant(agent_id="agent-001")
        grant.grant(_read_cap(expiry=_utc(+24)))
        grant.grant(Capability(resource="api:old", actions=["read"], expiry=_utc(-1)))
        active = grant.active_capabilities()
        assert len(active) == 1
        assert active[0].resource == "database:users"

    def test_revoke_by_resource_removes_all_matching(self) -> None:
        grant = CapabilityGrant(agent_id="agent-001")
        grant.grant(_read_cap("database:users"))
        grant.grant(_write_cap("database:users"))
        grant.grant(_read_cap("api:data"))
        removed = grant.revoke("database:users")
        assert removed == 2
        remaining = grant.all_capabilities()
        assert all(c.resource == "api:data" for c in remaining)

    def test_revoke_by_resource_and_action(self) -> None:
        grant = CapabilityGrant(agent_id="agent-001")
        grant.grant(_write_cap("api:data"))  # has read + write
        removed = grant.revoke("api:data", action="write")
        assert removed == 1

    def test_revoke_nonexistent_returns_zero(self) -> None:
        grant = CapabilityGrant(agent_id="agent-001")
        removed = grant.revoke("nonexistent:resource")
        assert removed == 0


# ---------------------------------------------------------------------------
# CapabilityChecker tests
# ---------------------------------------------------------------------------


class TestCapabilityCheckerInit:
    def test_default_strict_expiry(self) -> None:
        checker = CapabilityChecker()
        assert checker._strict_expiry is True

    def test_non_strict_mode(self) -> None:
        checker = CapabilityChecker(strict_expiry=False)
        assert checker._strict_expiry is False


class TestCapabilityCheckerRegistration:
    def test_register_agent(self) -> None:
        checker = CapabilityChecker()
        checker.register_agent("agent-001")
        assert "agent-001" in checker.registered_agents()

    def test_register_duplicate_raises(self) -> None:
        checker = CapabilityChecker()
        checker.register_agent("agent-001")
        with pytest.raises(ValueError, match="already registered"):
            checker.register_agent("agent-001")

    def test_grant_registers_agent_if_not_exists(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-x", _read_cap())
        assert "agent-x" in checker.registered_agents()


class TestCapabilityCheckerCheck:
    def test_check_allows_when_capability_present(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _write_cap())
        result = checker.check("agent-001", "database:users", "read")
        assert result.allowed is True
        assert result.capability is not None

    def test_check_denies_unknown_agent(self) -> None:
        checker = CapabilityChecker()
        result = checker.check("unknown-agent", "database:users", "read")
        assert result.allowed is False
        assert "no registered capabilities" in result.reason

    def test_check_denies_unlisted_action(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _read_cap())
        result = checker.check("agent-001", "database:users", "delete")
        assert result.allowed is False

    def test_check_denies_wrong_resource(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _read_cap("api:data"))
        result = checker.check("agent-001", "database:users", "read")
        assert result.allowed is False

    def test_check_denies_expired_capability_in_strict_mode(self) -> None:
        checker = CapabilityChecker(strict_expiry=True)
        expired_cap = Capability(
            resource="api:data",
            actions=["read"],
            expiry=_utc(-1),
        )
        checker.grant_capability("agent-001", expired_cap)
        result = checker.check("agent-001", "api:data", "read")
        assert result.allowed is False
        assert "expired" in result.reason

    def test_check_allows_expired_capability_in_non_strict_mode(self) -> None:
        checker = CapabilityChecker(strict_expiry=False)
        expired_cap = Capability(
            resource="api:data",
            actions=["read"],
            expiry=_utc(-1),
        )
        checker.grant_capability("agent-001", expired_cap)
        result = checker.check("agent-001", "api:data", "read")
        assert result.allowed is True

    def test_check_result_to_dict(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _read_cap())
        result = checker.check("agent-001", "database:users", "read")
        data = result.to_dict()
        assert "allowed" in data
        assert "reason" in data
        assert "capability" in data


class TestCapabilityCheckerRevoke:
    def test_revoke_removes_capability(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _read_cap())
        removed = checker.revoke_capability("agent-001", "database:users")
        assert removed >= 1
        result = checker.check("agent-001", "database:users", "read")
        assert result.allowed is False

    def test_revoke_nonexistent_agent_returns_zero(self) -> None:
        checker = CapabilityChecker()
        removed = checker.revoke_capability("ghost", "api:data")
        assert removed == 0


class TestListAgentCapabilities:
    def test_list_active_only(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _read_cap(expiry=_utc(+24)))
        checker.grant_capability(
            "agent-001",
            Capability(resource="api:old", actions=["read"], expiry=_utc(-1)),
        )
        active = checker.list_agent_capabilities("agent-001")
        assert len(active) == 1

    def test_list_including_expired(self) -> None:
        checker = CapabilityChecker()
        checker.grant_capability("agent-001", _read_cap(expiry=_utc(+24)))
        checker.grant_capability(
            "agent-001",
            Capability(resource="api:old", actions=["read"], expiry=_utc(-1)),
        )
        all_caps = checker.list_agent_capabilities("agent-001", include_expired=True)
        assert len(all_caps) == 2

    def test_list_unknown_agent_returns_empty(self) -> None:
        checker = CapabilityChecker()
        caps = checker.list_agent_capabilities("unknown")
        assert caps == []
