"""Tests for agent_identity.server.routes."""
from __future__ import annotations

import pytest

from agent_identity.server import routes


@pytest.fixture(autouse=True)
def reset_server_state() -> None:
    """Reset module-level state before each test."""
    routes.reset_state()


class TestHandleCreateIdentity:
    def test_creates_valid_identity(self) -> None:
        body = {
            "agent_id": "agent-001",
            "display_name": "My Agent",
            "organization": "AumOS",
            "capabilities": ["read", "write"],
        }
        status, data = routes.handle_create_identity(body)

        assert status == 201
        assert data["agent_id"] == "agent-001"
        assert data["display_name"] == "My Agent"
        assert data["organization"] == "AumOS"
        assert "read" in data["capabilities"]

    def test_creates_identity_with_did(self) -> None:
        body = {
            "agent_id": "agent-did",
            "display_name": "DID Agent",
            "organization": "AumOS",
            "did": "did:key:z6MkTest",
        }
        status, data = routes.handle_create_identity(body)

        assert status == 201
        assert data["did"] == "did:key:z6MkTest"

    def test_rejects_duplicate_agent_id(self) -> None:
        body = {
            "agent_id": "agent-dup",
            "display_name": "Agent",
            "organization": "Org",
        }
        routes.handle_create_identity(body)
        status, data = routes.handle_create_identity(body)

        assert status == 409
        assert "error" in data

    def test_rejects_missing_agent_id(self) -> None:
        body = {"display_name": "No ID Agent", "organization": "Org"}
        status, data = routes.handle_create_identity(body)

        assert status == 422
        assert "error" in data

    def test_rejects_empty_agent_id(self) -> None:
        body = {"agent_id": "   ", "display_name": "Agent", "organization": "Org"}
        status, data = routes.handle_create_identity(body)

        assert status == 422

    def test_created_at_is_iso_format(self) -> None:
        body = {
            "agent_id": "agent-time",
            "display_name": "Time Agent",
            "organization": "AumOS",
        }
        status, data = routes.handle_create_identity(body)

        assert status == 201
        # Should be parseable as an ISO datetime string
        from datetime import datetime
        datetime.fromisoformat(data["registered_at"])

    def test_active_is_true_by_default(self) -> None:
        body = {
            "agent_id": "agent-active",
            "display_name": "Active Agent",
            "organization": "AumOS",
        }
        status, data = routes.handle_create_identity(body)

        assert status == 201
        assert data["active"] is True


class TestHandleVerify:
    def test_verifies_registered_active_agent(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "verify-agent",
                "display_name": "Verified",
                "organization": "AumOS",
                "capabilities": ["search", "write"],
            }
        )
        status, data = routes.handle_verify(
            {
                "agent_id": "verify-agent",
                "claimed_capabilities": ["search"],
            }
        )

        assert status == 200
        assert data["verified"] is True
        assert data["active"] is True

    def test_fails_for_unregistered_agent(self) -> None:
        status, data = routes.handle_verify({"agent_id": "not-registered"})

        assert status == 200
        assert data["verified"] is False
        assert data["active"] is False

    def test_fails_for_missing_capabilities(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "limited-agent",
                "display_name": "Limited",
                "organization": "AumOS",
                "capabilities": ["read"],
            }
        )
        status, data = routes.handle_verify(
            {
                "agent_id": "limited-agent",
                "claimed_capabilities": ["read", "admin"],
            }
        )

        assert status == 200
        assert data["verified"] is False
        assert "admin" in data["missing_capabilities"]

    def test_verify_without_claimed_capabilities(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "simple-agent",
                "display_name": "Simple",
                "organization": "AumOS",
            }
        )
        status, data = routes.handle_verify({"agent_id": "simple-agent"})

        assert status == 200
        assert data["active"] is True

    def test_rejects_invalid_body(self) -> None:
        # Missing agent_id
        body = {"claimed_capabilities": ["read"]}
        status, data = routes.handle_verify(body)

        assert status == 422


class TestHandleGetTrust:
    def test_returns_trust_for_registered_agent(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "trust-agent",
                "display_name": "Trust Test",
                "organization": "AumOS",
            }
        )
        status, data = routes.handle_get_trust("trust-agent")

        assert status == 200
        assert data["agent_id"] == "trust-agent"
        assert "composite" in data
        assert "level" in data
        assert "dimensions" in data
        assert "timestamp" in data

    def test_returns_404_for_missing_agent(self) -> None:
        status, data = routes.handle_get_trust("nonexistent-trust-agent")

        assert status == 404
        assert "error" in data

    def test_trust_composite_is_numeric(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "trust-numeric",
                "display_name": "Numeric Trust",
                "organization": "AumOS",
            }
        )
        status, data = routes.handle_get_trust("trust-numeric")

        assert status == 200
        assert isinstance(data["composite"], float | int)
        assert data["composite"] >= 0

    def test_trust_dimensions_present(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "trust-dims",
                "display_name": "Dimensions",
                "organization": "AumOS",
            }
        )
        status, data = routes.handle_get_trust("trust-dims")

        assert status == 200
        assert len(data["dimensions"]) >= 1


class TestHandleHealth:
    def test_returns_ok_status(self) -> None:
        status, data = routes.handle_health()

        assert status == 200
        assert data["status"] == "ok"
        assert data["service"] == "agent-identity"

    def test_reports_identity_count(self) -> None:
        routes.handle_create_identity(
            {"agent_id": "count-agent", "display_name": "Counter", "organization": "Org"}
        )

        status, data = routes.handle_health()

        assert status == 200
        assert data["identity_count"] == 1

    def test_zero_count_initially(self) -> None:
        status, data = routes.handle_health()

        assert data["identity_count"] == 0
