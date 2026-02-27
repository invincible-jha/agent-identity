"""Integration tests for agent-native identity.

Tests the full lifecycle: create → grant/restrict → sign → verify → enforce.
"""
from __future__ import annotations

import datetime
import uuid

import pytest

from agent_identity.native.capability import Capability
from agent_identity.native.identity import AgentIdentity
from agent_identity.native.restriction import Enforcement, Restriction, RestrictionViolationError
from agent_identity.native.token import (
    IdentityToken,
    TokenExpiredError,
    TokenTamperedError,
)


SECRET = b"integration-test-secret-key"


# ---------------------------------------------------------------------------
# Happy path: create → sign → verify → enforce
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    def test_create_sign_verify_full_round_trip(self) -> None:
        """Create an identity, sign it, verify it, and confirm capabilities."""
        identity = AgentIdentity.create(
            name="invoice-processor",
            owner="finance-team",
            ttl_seconds=3600,
            metadata={"version": "1.0"},
        )
        identity.grant_capability(Capability(action="read", resource="db:invoices"))
        identity.grant_capability(Capability(action="write", resource="db:processed"))
        identity.add_restriction(Restriction(action="delete", reason="immutable records"))

        # Sign
        token = IdentityToken.sign(identity, secret=SECRET)
        assert isinstance(token, str)
        assert len(token.split(".")) == 3

        # Verify
        recovered = IdentityToken.verify(token, secret=SECRET)

        # Identity fields preserved
        assert recovered.agent_id == identity.agent_id
        assert recovered.name == "invoice-processor"
        assert recovered.owner == "finance-team"
        assert recovered.metadata == {"version": "1.0"}

        # Capabilities preserved
        assert recovered.has_capability("read", "db:invoices")
        assert recovered.has_capability("write", "db:processed")
        assert not recovered.has_capability("delete", "db:invoices")

        # Restrictions enforced
        recovered.enforce_restrictions("read")   # allowed — no restriction
        with pytest.raises(RestrictionViolationError):
            recovered.enforce_restrictions("delete")

    def test_no_ttl_identity_does_not_expire(self) -> None:
        identity = AgentIdentity.create(name="permanent-agent", owner="ops", ttl_seconds=None)
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert not recovered.is_expired()

    def test_wildcard_capability_grants_all_access(self) -> None:
        identity = AgentIdentity.create(name="superuser-bot", owner="admin")
        identity.grant_capability(Capability(action="*", resource="*"))
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert recovered.has_capability("read", "db:classified")
        assert recovered.has_capability("delete", "s3:bucket")
        assert recovered.has_capability("execute", "lambda:function")


# ---------------------------------------------------------------------------
# Security: expired tokens rejected
# ---------------------------------------------------------------------------


class TestExpiredIdentity:
    def test_expired_token_raises_at_verify(self) -> None:
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
        identity = AgentIdentity(
            agent_id=str(uuid.uuid4()),
            name="short-lived",
            owner="alice",
            ttl_seconds=10,  # 10s TTL
            created_at=past,  # created 2 hours ago
        )
        token = IdentityToken.sign(identity, secret=SECRET)
        with pytest.raises(TokenExpiredError):
            IdentityToken.verify(token, secret=SECRET)


# ---------------------------------------------------------------------------
# Security: tampered tokens rejected
# ---------------------------------------------------------------------------


class TestTamperedToken:
    def test_tampered_signature_rejected(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        token = IdentityToken.sign(identity, secret=SECRET)

        # Flip a character in the signature
        parts = token.split(".")
        tampered_sig = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
        tampered_token = ".".join(parts[:2] + [tampered_sig])

        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(tampered_token, secret=SECRET)

    def test_different_secret_rejected(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        token = IdentityToken.sign(identity, secret=SECRET)
        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(token, secret=b"attacker-key")


# ---------------------------------------------------------------------------
# Capability TTL integration
# ---------------------------------------------------------------------------


class TestCapabilityTTL:
    def test_expired_capability_not_granted_after_verify(self) -> None:
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        expired_cap = Capability(
            action="read",
            resource="db:temp",
            ttl_seconds=100,  # TTL expired 100s ago
            granted_at=past,
        )
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(expired_cap)

        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)

        # The capability was serialized into the token but should be expired
        assert not recovered.has_capability("read", "db:temp", check_expiry=True)

    def test_non_expired_capability_still_valid_after_verify(self) -> None:
        identity = AgentIdentity.create(name="agent", owner="alice")
        identity.grant_capability(Capability(action="read", resource="db:live", ttl_seconds=3600))

        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)

        assert recovered.has_capability("read", "db:live", check_expiry=True)


# ---------------------------------------------------------------------------
# Multiple agents with separate secrets
# ---------------------------------------------------------------------------


class TestMultipleAgents:
    def test_two_agents_cannot_use_each_others_tokens(self) -> None:
        identity_a = AgentIdentity.create(name="agent-a", owner="alice")
        identity_b = AgentIdentity.create(name="agent-b", owner="bob")

        secret_a = b"secret-for-agent-a"
        secret_b = b"secret-for-agent-b"

        token_a = IdentityToken.sign(identity_a, secret=secret_a)
        token_b = IdentityToken.sign(identity_b, secret=secret_b)

        # Each token verifies with its own secret
        recovered_a = IdentityToken.verify(token_a, secret=secret_a)
        recovered_b = IdentityToken.verify(token_b, secret=secret_b)

        assert recovered_a.agent_id == identity_a.agent_id
        assert recovered_b.agent_id == identity_b.agent_id

        # Cross-verify fails
        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(token_a, secret=secret_b)

        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(token_b, secret=secret_a)

    def test_restriction_enforcement_independent_per_agent(self) -> None:
        read_agent = AgentIdentity.create(name="reader", owner="ops")
        read_agent.grant_capability(Capability(action="read", resource="db:logs"))

        admin_agent = AgentIdentity.create(name="admin", owner="ops")
        admin_agent.grant_capability(Capability(action="*", resource="*"))

        secret = b"shared-ops-secret"
        token_reader = IdentityToken.sign(read_agent, secret=secret)
        token_admin = IdentityToken.sign(admin_agent, secret=secret)

        recovered_reader = IdentityToken.verify(token_reader, secret=secret)
        recovered_admin = IdentityToken.verify(token_admin, secret=secret)

        # Reader can only read
        assert recovered_reader.has_capability("read", "db:logs")
        assert not recovered_reader.has_capability("write", "db:logs")

        # Admin can do anything
        assert recovered_admin.has_capability("write", "db:logs")
        assert recovered_admin.has_capability("delete", "db:logs")


# ---------------------------------------------------------------------------
# Restriction interaction with capabilities
# ---------------------------------------------------------------------------


class TestRestrictionCapabilityInteraction:
    def test_restriction_overrides_wildcard_capability(self) -> None:
        """Even with *, a BLOCK restriction prevents the action."""
        identity = AgentIdentity.create(name="constrained-admin", owner="ops")
        identity.grant_capability(Capability(action="*", resource="*"))
        identity.add_restriction(
            Restriction(action="drop-db", reason="Never allowed", enforcement=Enforcement.BLOCK)
        )

        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)

        # Has capability
        assert recovered.has_capability("drop-db", "db:prod")

        # But restriction blocks it
        with pytest.raises(RestrictionViolationError):
            recovered.enforce_restrictions("drop-db")

    def test_alert_restriction_allows_with_logging(self) -> None:
        identity = AgentIdentity.create(name="audited-agent", owner="audit")
        identity.add_restriction(
            Restriction(action="read", enforcement=Enforcement.ALERT, reason="audited")
        )

        # enforce_restrictions should NOT raise for ALERT
        identity.enforce_restrictions("read")
