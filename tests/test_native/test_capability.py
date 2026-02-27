"""Tests for Capability — typed capability with wildcard matching."""
from __future__ import annotations

import datetime

import pytest

from agent_identity.native.capability import Capability


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_basic_capability(self) -> None:
        cap = Capability(action="read", resource="db:users")
        assert cap.action == "read"
        assert cap.resource == "db:users"
        assert cap.constraints == {}

    def test_with_constraints(self) -> None:
        cap = Capability(
            action="read",
            resource="db:orders",
            constraints={"max_rows": 1000},
        )
        assert cap.constraints["max_rows"] == 1000

    def test_granted_at_defaults_to_now(self) -> None:
        before = datetime.datetime.now(datetime.timezone.utc)
        cap = Capability(action="write", resource="bucket")
        after = datetime.datetime.now(datetime.timezone.utc)
        assert before <= cap.granted_at <= after

    def test_no_ttl_by_default(self) -> None:
        cap = Capability(action="read", resource="*")
        assert cap.ttl_seconds is None


# ---------------------------------------------------------------------------
# matches() — action + resource
# ---------------------------------------------------------------------------


class TestMatches:
    def test_exact_match(self) -> None:
        cap = Capability(action="read", resource="db:users")
        assert cap.matches("read", "db:users")

    def test_wrong_action(self) -> None:
        cap = Capability(action="read", resource="db:users")
        assert not cap.matches("write", "db:users")

    def test_wrong_resource(self) -> None:
        cap = Capability(action="read", resource="db:users")
        assert not cap.matches("read", "db:orders")

    def test_wildcard_action(self) -> None:
        cap = Capability(action="*", resource="db:users")
        assert cap.matches("read", "db:users")
        assert cap.matches("write", "db:users")
        assert cap.matches("delete", "db:users")

    def test_wildcard_resource(self) -> None:
        cap = Capability(action="read", resource="*")
        assert cap.matches("read", "db:users")
        assert cap.matches("read", "db:orders")
        assert cap.matches("read", "s3:bucket")

    def test_both_wildcards(self) -> None:
        cap = Capability(action="*", resource="*")
        assert cap.matches("anything", "anywhere")

    def test_wildcard_does_not_match_empty_string(self) -> None:
        cap = Capability(action="*", resource="db:users")
        # Empty string is technically valid but different from wildcard
        assert cap.matches("", "db:users")


# ---------------------------------------------------------------------------
# matches_action / matches_resource
# ---------------------------------------------------------------------------


class TestMatchesSingle:
    def test_matches_action_exact(self) -> None:
        cap = Capability(action="write", resource="bucket")
        assert cap.matches_action("write")
        assert not cap.matches_action("read")

    def test_matches_action_wildcard(self) -> None:
        cap = Capability(action="*", resource="bucket")
        assert cap.matches_action("anything")

    def test_matches_resource_exact(self) -> None:
        cap = Capability(action="read", resource="db:logs")
        assert cap.matches_resource("db:logs")
        assert not cap.matches_resource("db:users")

    def test_matches_resource_wildcard(self) -> None:
        cap = Capability(action="read", resource="*")
        assert cap.matches_resource("any-resource")


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_no_ttl_never_expires(self) -> None:
        cap = Capability(action="read", resource="db", ttl_seconds=None)
        assert not cap.is_expired()

    def test_future_ttl_not_expired(self) -> None:
        cap = Capability(action="read", resource="db", ttl_seconds=3600)
        assert not cap.is_expired()

    def test_past_ttl_is_expired(self) -> None:
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        cap = Capability(
            action="read",
            resource="db",
            ttl_seconds=100,
            granted_at=past,
        )
        assert cap.is_expired()

    def test_expires_at_with_ttl(self) -> None:
        cap = Capability(action="read", resource="db", ttl_seconds=3600)
        expiry = cap.expires_at()
        assert expiry is not None
        assert expiry > datetime.datetime.now(datetime.timezone.utc)

    def test_expires_at_none_without_ttl(self) -> None:
        cap = Capability(action="read", resource="db")
        assert cap.expires_at() is None


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_dict_round_trip(self) -> None:
        cap = Capability(
            action="read",
            resource="db:users",
            constraints={"limit": 100},
            ttl_seconds=3600,
        )
        d = cap.to_dict()
        recovered = Capability.from_dict(d)
        assert recovered.action == cap.action
        assert recovered.resource == cap.resource
        assert recovered.constraints == cap.constraints
        assert recovered.ttl_seconds == cap.ttl_seconds

    def test_to_dict_contains_required_keys(self) -> None:
        cap = Capability(action="write", resource="bucket")
        d = cap.to_dict()
        assert "action" in d
        assert "resource" in d
        assert "constraints" in d
        assert "ttl_seconds" in d
        assert "granted_at" in d

    def test_from_dict_no_ttl(self) -> None:
        d = {
            "action": "read",
            "resource": "db",
            "constraints": {},
            "ttl_seconds": None,
            "granted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        cap = Capability.from_dict(d)
        assert cap.ttl_seconds is None


# ---------------------------------------------------------------------------
# Str / repr
# ---------------------------------------------------------------------------


class TestStrRepr:
    def test_str_format(self) -> None:
        cap = Capability(action="read", resource="db:users")
        assert str(cap) == "read:db:users"

    def test_repr_contains_action_and_resource(self) -> None:
        cap = Capability(action="write", resource="s3:bucket")
        assert "write" in repr(cap)
        assert "s3:bucket" in repr(cap)
