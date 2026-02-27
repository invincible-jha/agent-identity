"""Tests for AgentIdentity — core per-agent identity model."""
from __future__ import annotations

import datetime
import uuid

import pytest

from agent_identity.native.capability import Capability
from agent_identity.native.identity import AgentIdentity
from agent_identity.native.restriction import Enforcement, Restriction, RestrictionViolationError


# ---------------------------------------------------------------------------
# Construction via AgentIdentity.create()
# ---------------------------------------------------------------------------


class TestCreate:
    def test_create_returns_agent_identity(self) -> None:
        identity = AgentIdentity.create(name="test-agent", owner="alice")
        assert isinstance(identity, AgentIdentity)

    def test_create_generates_unique_agent_id(self) -> None:
        id1 = AgentIdentity.create(name="agent-a", owner="alice")
        id2 = AgentIdentity.create(name="agent-b", owner="alice")
        assert id1.agent_id != id2.agent_id

    def test_create_agent_id_is_uuid(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="bob")
        uuid.UUID(identity.agent_id)  # should not raise

    def test_create_name_and_owner(self) -> None:
        identity = AgentIdentity.create(name="billing-bot", owner="finance")
        assert identity.name == "billing-bot"
        assert identity.owner == "finance"

    def test_create_empty_capabilities_by_default(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        assert identity.capabilities == []

    def test_create_empty_restrictions_by_default(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        assert identity.restrictions == []

    def test_create_with_initial_capabilities(self) -> None:
        caps = [Capability(action="read", resource="db")]
        identity = AgentIdentity.create(name="agent", owner="alice", capabilities=caps)
        assert len(identity.capabilities) == 1

    def test_create_with_ttl(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice", ttl_seconds=3600)
        assert identity.ttl_seconds == 3600

    def test_create_with_metadata(self) -> None:
        identity = AgentIdentity.create(
            name="agent",
            owner="alice",
            metadata={"env": "production"},
        )
        assert identity.metadata["env"] == "production"

    def test_create_timestamp_is_utc(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        assert identity.created_at.tzinfo is not None


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_no_ttl_never_expires(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice", ttl_seconds=None)
        assert not identity.is_expired()

    def test_future_ttl_not_expired(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice", ttl_seconds=3600)
        assert not identity.is_expired()

    def test_past_ttl_is_expired(self) -> None:
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        identity = AgentIdentity(
            agent_id=str(uuid.uuid4()),
            name="old-agent",
            owner="alice",
            ttl_seconds=100,
            created_at=past,
        )
        assert identity.is_expired()

    def test_expires_at_with_ttl(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice", ttl_seconds=3600)
        expiry = identity.expires_at()
        assert expiry is not None
        assert expiry > datetime.datetime.now(datetime.timezone.utc)

    def test_expires_at_none_without_ttl(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        assert identity.expires_at() is None


# ---------------------------------------------------------------------------
# Capability management
# ---------------------------------------------------------------------------


class TestCapabilityManagement:
    def test_grant_capability(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        cap = Capability(action="read", resource="db:users")
        identity.grant_capability(cap)
        assert len(identity.capabilities) == 1

    def test_has_capability_true(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db:users"))
        assert identity.has_capability("read", "db:users")

    def test_has_capability_false_wrong_action(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db:users"))
        assert not identity.has_capability("write", "db:users")

    def test_has_capability_false_wrong_resource(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db:users"))
        assert not identity.has_capability("read", "db:orders")

    def test_wildcard_capability_matches_all(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="*", resource="*"))
        assert identity.has_capability("delete", "production-db")

    def test_revoke_capability(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db:users"))
        removed = identity.revoke_capability("read", "db:users")
        assert removed
        assert not identity.has_capability("read", "db:users")

    def test_revoke_nonexistent_returns_false(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        removed = identity.revoke_capability("delete", "db:users")
        assert not removed

    def test_has_capability_skips_expired(self) -> None:
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(
            Capability(
                action="read",
                resource="db",
                ttl_seconds=100,
                granted_at=past,
            )
        )
        assert not identity.has_capability("read", "db", check_expiry=True)
        assert identity.has_capability("read", "db", check_expiry=False)

    def test_get_capabilities_for_action(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db:users"))
        identity.grant_capability(Capability(action="read", resource="db:orders"))
        identity.grant_capability(Capability(action="write", resource="db:users"))
        read_caps = identity.get_capabilities_for("read")
        assert len(read_caps) == 2


# ---------------------------------------------------------------------------
# Restriction management
# ---------------------------------------------------------------------------


class TestRestrictionManagement:
    def test_add_restriction(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete", reason="no deletes"))
        assert len(identity.restrictions) == 1

    def test_is_restricted_true(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete", enforcement=Enforcement.BLOCK))
        assert identity.is_restricted("delete")

    def test_is_restricted_false_for_alert(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete", enforcement=Enforcement.ALERT))
        assert not identity.is_restricted("delete")

    def test_is_restricted_false_for_unrelated_action(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete", enforcement=Enforcement.BLOCK))
        assert not identity.is_restricted("read")

    def test_remove_restriction(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete"))
        removed = identity.remove_restriction("delete")
        assert removed
        assert not identity.is_restricted("delete")

    def test_remove_nonexistent_restriction_returns_false(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        assert not identity.remove_restriction("nonexistent")

    def test_enforce_restrictions_passes_for_allowed_action(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete"))
        identity.enforce_restrictions("read")  # should not raise

    def test_enforce_restrictions_raises_for_blocked_action(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.add_restriction(Restriction(action="delete", reason="no deletes"))
        with pytest.raises(RestrictionViolationError):
            identity.enforce_restrictions("delete")


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_dict_and_from_dict(self) -> None:
        identity = AgentIdentity.create(
            name="billing-bot",
            owner="finance",
            capabilities=[Capability(action="read", resource="db:invoices")],
            restrictions=[Restriction(action="delete", reason="no deletes")],
            ttl_seconds=3600,
            metadata={"env": "prod"},
        )
        d = identity.to_dict()
        recovered = AgentIdentity.from_dict(d)

        assert recovered.agent_id == identity.agent_id
        assert recovered.name == identity.name
        assert recovered.owner == identity.owner
        assert len(recovered.capabilities) == 1
        assert len(recovered.restrictions) == 1
        assert recovered.ttl_seconds == 3600
        assert recovered.metadata == {"env": "prod"}

    def test_to_dict_keys(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        d = identity.to_dict()
        for key in ("agent_id", "name", "owner", "capabilities", "restrictions",
                    "ttl_seconds", "created_at", "metadata"):
            assert key in d

    def test_from_dict_preserves_agent_id(self) -> None:
        fixed_id = str(uuid.uuid4())
        d = {
            "agent_id": fixed_id,
            "name": "test",
            "owner": "alice",
            "capabilities": [],
            "restrictions": [],
            "ttl_seconds": None,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metadata": {},
        }
        identity = AgentIdentity.from_dict(d)
        assert identity.agent_id == fixed_id


# ---------------------------------------------------------------------------
# Repr
# ---------------------------------------------------------------------------


class TestRepr:
    def test_repr_contains_name(self) -> None:
        identity = AgentIdentity.create(name="my-agent", owner="alice")
        assert "my-agent" in repr(identity)

    def test_repr_contains_capability_count(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db"))
        assert "1" in repr(identity)
